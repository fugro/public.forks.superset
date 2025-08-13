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
   Embed-aware SCM:
     - If header contains a Superset ACCESS TOKEN, log in the REAL user.
     - Otherwise fall back to native guest behavior (if you ever use guest tokens).
     - When a dashboard object isn't passed, resolve from URL and enforce RBAC,
       so unauthorized dashboard metadata does NOT render.
   """
   # ------------ Identity ------------
   def request_loader(self, request: Request) -> Optional[User]:
       print("\n[CSM] request_loader() called")
       if not feature_flag_manager.is_feature_enabled("EMBEDDED_SUPERSET"):
           print("[CSM] EMBEDDED_SUPERSET OFF → None")
           return None
       print(f"[CSM] URL: {request.url}")
       print(f"[CSM] Referrer: {request.referrer}")
       print(f"[CSM] Method: {request.method}")
       header_name = current_app.config.get("GUEST_TOKEN_HEADER_NAME", "X-GuestToken")
       raw = (
           request.headers.get(header_name)
           or request.form.get("guest_token")
           or request.headers.get("Authorization")
       )
       print(f"[CSM] Tokens present? {header_name}={bool(request.headers.get(header_name))} "
             f"form={bool(request.form.get('guest_token'))} Auth={bool(request.headers.get('Authorization'))}")
       if not raw:
           print("[CSM] No token → native guest flow")
           return self.get_guest_user_from_request(request)
       token = raw.replace("Bearer ", "")
       user = self._user_from_superset_access_token(token)
       if user:
           print(f"[CSM] Authenticated as REAL user: id={user.id}, username={user.username}, "
                 f"roles={[r.name for r in user.roles]}")
           return user
       print("[CSM] Header is not a Superset access token → native guest flow")
       return self.get_guest_user_from_request(request)
   def _user_from_superset_access_token(self, token: str) -> Optional[User]:
       try:
           payload = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
           print(f"[CSM] JWT decoded: sub={payload.get('sub')}, exp={payload.get('exp')}")
           user_id = payload.get("sub")
           if not user_id:
               return None
           user = self.get_session.query(self.user_model).filter_by(id=user_id).one_or_none()
           print(f"[CSM] User lookup sub={user_id} → {'FOUND' if user else 'NOT FOUND'}")
           return user
       except Exception as ex:
           print(f"[CSM] Access token decode failed: {ex}")
           return None
   # ------------ Helpers ------------
   def _extract_dashboard_from_url(self, url: str) -> Optional[str]:
       if not url:
           return None
       parsed = urllib.parse.urlparse(url)
       qs = urllib.parse.parse_qs(parsed.query)
       path = parsed.path or ""
       if qs.get("dashboard_id"):
           return str(qs["dashboard_id"][0])
       # /embedded/<uuid>
       m = re.search(r"/embedded/([0-9a-fA-F-]{36})(?:/|$)", path)
       if m:
           return m.group(1)
       # /api/v1/dashboard/<id|uuid>
       m = re.search(r"/api/v1/dashboard/([0-9a-fA-F-]{1,36})(?:/|$)", path)
       if m:
           return m.group(1)
       # /superset/dashboard/p/<uuid>
       m = re.search(r"/superset/dashboard/p/([0-9a-fA-F-]{36})(?:/|$)", path)
       if m:
           return m.group(1)
       # /superset/dashboard/<id>
       m = re.search(r"/superset/dashboard/(\d+)(?:/|$)", path)
       if m:
           return m.group(1)
       return None
   def _resolve_dashboard_when_none(self):
       if not has_request_context():
           return None
       from flask import request as flask_request
       from superset.models.dashboard import Dashboard as DashboardModel
       ref = (self._extract_dashboard_from_url(flask_request.url)
              or self._extract_dashboard_from_url(flask_request.referrer or ""))
       if not ref:
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
   # ------------ Authorization ------------
   def raise_for_access(self, dashboard=None, **kwargs):
       print("\n[CSM] raise_for_access() called")
       try:
           roles = [r.name for r in getattr(current_user, "roles", [])]
       except Exception:
           roles = []
       print(f"[CSM] current_user: auth={getattr(current_user, 'is_authenticated', None)} "
             f"anon={getattr(current_user, 'is_anonymous', None)} roles={roles}")
       # If endpoint didn't pass a dashboard (e.g. GET /api/v1/dashboard/<id>), resolve it and enforce.
       if dashboard is None:
           dashboard = self._resolve_dashboard_when_none()
       if dashboard is not None:
           print(f"[CSM] Dashboard: id={getattr(dashboard, 'id', None)} "
                 f"uuid={getattr(dashboard, 'uuid', None)} title={getattr(dashboard, 'dashboard_title', None)}")
       else:
           print("[CSM] Dashboard unresolved; delegating to default checks")
       # Only Admin bypasses
       if any(r == "Admin" for r in roles):
           print("[CSM] ALLOW: Admin bypass")
           return
       # Delegate to Superset's native checks (Dashboard RBAC + dataset perms)
       print("[CSM] Delegating to super().raise_for_access() …")
       return super().raise_for_access(dashboard=dashboard, **kwargs)