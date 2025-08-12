import urllib.parse
import jwt
from flask import Request
from flask_login import current_user
from superset.security import SupersetSecurityManager
from superset.extensions import feature_flag_manager
from flask_appbuilder.security.sqla.models import User
from superset.commands.dashboard.exceptions import DashboardAccessDeniedError

class CustomSecurityManager(SupersetSecurityManager):
    def request_loader(self, request: Request) -> User | None:
        if feature_flag_manager.is_feature_enabled("EMBEDDED_SUPERSET"):
            print(" Checking for embedded token...")
            try:
                return self.get_user_roles_from_app(request)
            except Exception as e:
                print("Error in request_loader:", str(e))
                return self.get_guest_user_from_request(request)
        return None

    def get_user_roles_from_app(self, request: Request) -> User | None:
        token = request.headers.get("x-guesttoken") or request.form.get("guest_token")
        if not token:
            return None

        user = self.validate_token_and_get_user(token)
        if not user:
            return None

        parsed_url = urllib.parse.urlparse(request.referrer or "")
        query_params = urllib.parse.parse_qs(parsed_url.query)
        dashboard_id = query_params.get("dashboard_id", [None])[0]

        guest_user_token = {
            "user": {
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
            "resources": [{"type": "dashboard", "id": str(dashboard_id)}] if dashboard_id else []
        }

        return self.guest_user_cls(
            token=guest_user_token,
            roles=user.roles,
        )

    def validate_token_and_get_user(self, token: str) -> User | None:
        try:
            decoded_token = jwt.decode(token.replace("Bearer ", ""), options={"verify_signature": False})
            user_id = decoded_token.get("sub")
            if user_id:
                return self.get_session.query(self.user_model).filter_by(id=user_id).first()
        except Exception as e:
            print("Token decoding error:", str(e))
        return None

    def raise_for_access(self, dashboard=None, **kwargs):
        user_roles = [role.name for role in current_user.roles]

        privileged_roles = {
            "Admin",
            # "Alpha",
            "Gamma",
            # "dataSourceAccess",
            # "Octopus_Geodata_Maintainer",
            # "Octopus_Non_Tech_Editor",
        }

        if any(role in privileged_roles for role in user_roles):
            print("\n\n\n\n Access granted for user:", current_user.username, "with user roles:", user_roles, "\n\n\n\n")
            return

        #  Guest token-based access check
        if self.is_guest_user():
            token_resources = getattr(current_user, "token", {}).get("resources", [])
            allowed_ids = {str(r["id"]) for r in token_resources if r["type"] == "dashboard"}

            if dashboard and (str(dashboard.id) in allowed_ids or str(dashboard.uuid) in allowed_ids):
                return
            raise DashboardAccessDeniedError()

        #  Fallback to default Superset access control
        super().raise_for_access(dashboard=dashboard, **kwargs)



