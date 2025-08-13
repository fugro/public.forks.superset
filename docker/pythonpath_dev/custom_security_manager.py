import re
import urllib.parse
from typing import Optional
import jwt
from flask import Request, current_app, has_request_context
from flask_login import current_user
from superset.security import SupersetSecurityManager
from superset.extensions import feature_flag_manager
from superset.commands.dashboard.exceptions import DashboardAccessDeniedError
from flask_appbuilder.security.sqla.models import User

class CustomSecurityManager(SupersetSecurityManager):
   """
   Embed-aware security manager with verbose debug prints and robust gating:
     - Accept Superset user access token via X-GuestToken (or Authorization).
     - Build a guest user carrying the real user's roles (MUST pass token=...).
     - Attach BOTH `.token` and `.guest_token`.
     - If dashboard=None in raise_for_access, resolve from URL and enforce.
     - Treat /api/v1/chart/data as NON-guest (prevents 'guest cannot modify chart payload').
     - All request/current_app access is guarded by has_request_context().
   """
    # Treat chart-data as non-guest so dashboards can pass extra_form_data
   def is_guest_user(self, user=None, *_, **__):
       """
       Superset expects is_guest_user(self, user).
       We keep compatibility and only treat /api/v1/chart/data as non-guest.
       """
       try:
           if has_request_context():
               from flask import request as flask_request  # import inside to avoid context issues
               path = (flask_request.path or "")
               if path.startswith("/api/v1/chart/data"):
                   return False
       except Exception as ex:
           print(f"[CSM] is_guest_user() path check skipped due to: {ex}")
       # IMPORTANT: pass user through
       return super().is_guest_user(user)
   # ----------------------------
   # Request loading (identity)
   # ----------------------------
   def request_loader(self, request: Request) -> Optional[User]:
       print("\n[CSM] request_loader() called")
       if not feature_flag_manager.is_feature_enabled("EMBEDDED_SUPERSET"):
           print("[CSM] EMBEDDED_SUPERSET is OFF → returning None")
           return None
       print(f"[CSM] URL: {request.url}")
       print(f"[CSM] Referrer: {request.referrer}")
       print(f"[CSM] Method: {request.method}")
       header_name = current_app.config.get("GUEST_TOKEN_HEADER_NAME", "X-GuestToken")
       header_token = request.headers.get(header_name)
       form_token = request.form.get("guest_token")
       auth_token = request.headers.get("Authorization")
       print(f"[CSM] Checking tokens… {header_name} present? {bool(header_token)} | "
             f"form guest_token present? {bool(form_token)} | Authorization present? {bool(auth_token)}")
       raw = header_token or form_token or auth_token
       if not raw:
           print("[CSM] No token found → fallback to native guest user")
           return self.get_guest_user_from_request(request)
       token = raw.replace("Bearer ", "")
       user = self._user_from_superset_access_token(token)
       if not user:
           print("[CSM] Token did NOT decode to a Superset user → fallback to native guest user")
           return self.get_guest_user_from_request(request)
       print(f"[CSM] Superset user resolved from token: id={user.id}, username={user.username}, "
             f"roles={[r.name for r in user.roles]}")
       dashboard_ref = self._extract_dashboard_from_request(request)
       print(f"[CSM] Extracted dashboard_ref for this request: {dashboard_ref}")
       guest_user_token = {
           "user": {
               "username": user.username,
               "first_name": user.first_name,
               "last_name": user.last_name,
           },
           "resources": (
               [{"type": "dashboard", "id": str(dashboard_ref)}] if dashboard_ref else []
           ),
       }
       print(f"[CSM] guest_user_token.resources = {guest_user_token.get('resources')}")
       # IMPORTANT: pass token=... to constructor so resources persist
       guest = self.guest_user_cls(token=guest_user_token, roles=user.roles)
       # Also attach both attributes for safety across versions/proxies
       setattr(guest, "token", guest_user_token)
       setattr(guest, "guest_token", guest_user_token)
       print(f"[CSM] Returning guest user with roles: {[r.name for r in guest.roles]}")
       return guest
   def _user_from_superset_access_token(self, token: str) -> Optional[User]:
       try:
           payload = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
           print(f"[CSM] JWT decoded. claims: sub={payload.get('sub')}, iss={payload.get('iss')}, "
                 f"aud={payload.get('aud')}, exp={payload.get('exp')}")
           user_id = payload.get("sub")
           if not user_id:
               print("[CSM] No 'sub' in token payload → cannot resolve user")
               return None
           user = self.get_session.query(self.user_model).filter_by(id=user_id).one_or_none()
           print(f"[CSM] DB lookup for user_id={user_id} → {'FOUND' if user else 'NOT FOUND'}")
           return user
       except Exception as ex:
           print(f"[CSM] Access token decode FAILED: {ex}")
           return None
   def _extract_dashboard_from_request(self, request: Request) -> Optional[str]:
       def _try(url: str, label: str) -> Optional[str]:
           if not url:
               print(f"[CSM] extractor: {label}: empty"); return None
           parsed = urllib.parse.urlparse(url)
           qs = urllib.parse.parse_qs(parsed.query)
           path = parsed.path or ""
           print(f"[CSM] extractor: {label}: path={path} | query={qs}")
           if qs.get("dashboard_id"):
               val = str(qs["dashboard_id"][0]); print(f"[CSM] extractor: {label}: matched query dashboard_id={val}"); return val
           m = re.search(r"/embedded/([0-9a-fA-F-]{36})(?:/|$)", path)
           if m: val = m.group(1); print(f"[CSM] extractor: {label}: matched /embedded/<uuid> = {val}"); return val
           m = re.search(r"/api/v1/dashboard/([0-9a-fA-F-]{1,36})(?:/|$)", path)
           if m: val = m.group(1); print(f"[CSM] extractor: {label}: matched /api/v1/dashboard/<id|uuid> = {val}"); return val
           m = re.search(r"/superset/dashboard/p/([0-9a-fA-F-]{36})(?:/|$)", path)
           if m: val = m.group(1); print(f"[CSM] extractor: {label}: matched /superset/dashboard/p/<uuid> = {val}"); return val
           m = re.search(r"/superset/dashboard/(\d+)(?:/|$)", path)
           if m: val = m.group(1); print(f"[CSM] extractor: {label}: matched /superset/dashboard/<id> = {val}"); return val
           print(f"[CSM] extractor: {label}: no match"); return None
       return _try(request.url or "", "request.url") or _try(request.referrer or "", "request.referrer")
   def _resources_from_current_user_or_request(self) -> set[str]:
       token_obj = getattr(current_user, "token", None)
       guest_token_obj = getattr(current_user, "guest_token", None)
       res = []
       if isinstance(token_obj, dict):
           res = token_obj.get("resources", []) or []
       if not res and isinstance(guest_token_obj, dict):
           res = guest_token_obj.get("resources", []) or []
       if not res and has_request_context():
           from flask import request as flask_request
           dash_ref = self._extract_dashboard_from_request(flask_request)
           if dash_ref:
               res = [{"type": "dashboard", "id": str(dash_ref)}]
       allowed = {str(r.get("id")) for r in res if r.get("type") == "dashboard"}
       print(f"[CSM] _resources_from_current_user_or_request → "
             f"token_obj={'yes' if isinstance(token_obj, dict) else 'no'}, "
             f"guest_token_obj={'yes' if isinstance(guest_token_obj, dict) else 'no'}, "
             f"resolved_allowed={allowed}")
       return allowed
   def _resolve_dashboard_when_none(self):
       """When raise_for_access(dashboard=None), try to resolve from request path."""
       if not has_request_context():
           print("[CSM] _resolve_dashboard_when_none: no request context")
           return None
       from flask import request as flask_request
       # Lazy import to avoid import-time context coupling
       from superset.models.dashboard import Dashboard as DashboardModel
       ref = self._extract_dashboard_from_request(flask_request)
       if not ref:
           print("[CSM] _resolve_dashboard_when_none: no ref found")
           return None
       q = self.get_session.query(DashboardModel)
       dash = None
       if re.fullmatch(r"\d+", ref):
           dash = q.filter(DashboardModel.id == int(ref)).one_or_none()
       if dash is None:
           dash = q.filter(DashboardModel.uuid == ref).one_or_none()
       print(f"[CSM] _resolve_dashboard_when_none: ref={ref} → "
             f"{'FOUND id='+str(dash.id) if dash else 'NOT FOUND'}")
       return dash
   # ----------------------------
   # Authorization gatekeeper
   # ----------------------------
   def raise_for_access(self, dashboard=None, **kwargs):
        print("\n[CSM] raise_for_access() called")
        try:
           roles = [r.name for r in getattr(current_user, "roles", [])]
        except Exception:
           roles = []
        print(f"[CSM] current_user: is_authenticated={getattr(current_user, 'is_authenticated', None)} "
             f"is_anonymous={getattr(current_user, 'is_anonymous', None)} "
             f"is_guest={super().is_guest_user(current_user)} roles={roles}")
       # If dashboard is None (e.g., GET /api/v1/dashboard/<id>), resolve and enforce
        if dashboard is None:
           dashboard = self._resolve_dashboard_when_none()
        if dashboard is not None:
           print(f"[CSM] Dashboard object: id={getattr(dashboard, 'id', None)} "
                 f"uuid={getattr(dashboard, 'uuid', None)} title={getattr(dashboard, 'dashboard_title', None)}")
        else:
           print("[CSM] Dashboard object is None and could not be resolved")
       # Admin bypass only
        if any(r == "Admin" for r in roles):
           print("[CSM] ALLOW: Admin bypass")
           return
       # Resource gate for guest users
       # (use super().is_guest_user() so our chart-data override doesn't disable this)
        if super().is_guest_user() and dashboard is not None:
           allowed = self._resources_from_current_user_or_request()
           if str(dashboard.id) in allowed or str(dashboard.uuid) in allowed:
               print("[CSM] Resource match → continue to native RBAC checks")
           else:
               print("[CSM] DENY: dashboard id/uuid not in allowed set")
               raise DashboardAccessDeniedError()
        print("[CSM] Delegating to super().raise_for_access() for native checks…")
        return super().raise_for_access(dashboard=dashboard, **kwargs)