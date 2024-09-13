from flask import redirect, flash, request
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.security.views import expose
from flask_login import login_user
from superset.security import SupersetSecurityManager
import jwt
import json
from jwt import PyJWKClient
import base64

# Function to decode URL-safe base64 encoded strings
def decode(encoded_string: str) -> str:
    try:
        # Decode the URL-safe base64 encoded string
        decoded_bytes = base64.urlsafe_b64decode(encoded_string)
        print("Decoded URL-safe base64 encoded string", decoded_bytes)
        # Convert bytes to string (assuming UTF-8 encoding)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        flash(f'Base64 decoding error: {str(e)}', 'danger')
        return None

class CustomAuthDBView(AuthDBView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        print("Login endpoint hit")  # Debugging
        token = request.args.get('token')
        # token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyJ9.eyJhdWQiOiJkOWJmNTYwZC01MDJlLTQzNTEtYWRjZi0wOGZjNWQwYzk2NDMiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNmU2MDMyODktNWU0Ni00ZTI2LWFjN2MtMDNhODU0MjBhOWE1L3YyLjAiLCJpYXQiOjE3MjIzMzQ4NTQsIm5iZiI6MTcyMjMzNDg1NCwiZXhwIjoxNzIyMzM4NzU0LCJhaW8iOiJBVlFBcS84WEFBQUFBOU9LaWJLK1ZrRHRjUVdtQ29iNG10TDRkRkhFbXRoVmxaTlFVdFNlbFlLRG9BeUVYZlRuUWsvTWxXcUZOK3g4M0R5b2ZoUVkvTGtncmpsN1AyRXpTTXJHUXgwVGpjR0FmT0RsVUMyRXhxMD0iLCJuYW1lIjoiQ0lSSkFOIElvbnV0LVJhenZhbiIsIm5vbmNlIjoiYzU3YTZjMjYtNGZhZC00MGUyLTk0ZmYtYjc4NjFhZWQxMTMyIiwib2lkIjoiNjZjYTgzOTEtNDYzYy00MTE4LTkyZTYtZDIzOGVkOGUyY2JlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiaW9udXQtcmF6dmFuLmNpcmphbkB0aGFsZXNncm91cC5jb20iLCJyaCI6IjAuQVNFQWlUSmdia1plSms2c2ZBT29WQ0NwcFExV3Y5a3VVRkZEcmM4SV9GME1sa01oQURFLiIsInN1YiI6ImZocC1xa1ktZ2g2S3ByTzh0bUNqNUxiQmJFcVlmUXhyRFJQMEc0dUdObkEiLCJ0aWQiOiI2ZTYwMzI4OS01ZTQ2LTRlMjYtYWM3Yy0wM2E4NTQyMGE5YTUiLCJ1dGkiOiJGRlN6emRfMkdVS2VnYWZUU3E4U0FBIiwidmVyIjoiMi4wIn0.dw6i0WMe6HYSAhmmgjOvwRUWk7gQ3tHBC6xRPe23viX5ZkyvPl03MdOv3YYnGLFQZfV9x5vhf--U8ZLiXSBO3-ntJ3pez1n59JruZAF81e7KDmWZOeuV5a1Cl9pkwacyXyXYwtkBQblVSfbiFvYIXY-2R1GLQBduiuDz_l5Qlic6wSRImJIQjX2aFMU2kUkwngq_C_HcERLAOBYaPQQx12MewU1TXOYvbrG9aSh2tebpPzvn5vDYb9O3ZiUOSfrxSc5mx_0h5wdV8jh90oVyCzR2XFzk_31m3tMy3BA5axPY89cW_CsmdaJuhLaIfwVlFjQoLKYETnmRJOz8IeUwAg'
        dashboard_id = request.args.get('dashboard_id')
        sm = self.appbuilder.sm
        session = sm.get_session

        if not token:
            return super(CustomAuthDBView, self).login()

        try:
            # Decode the JWT token without verification (if you don't need to verify the signature)
            payload = jwt.decode(token, options={"verify_signature": False})

            if payload:
                print("Payload****", payload)
                user_id = payload.get("sub")
                user_role = payload.get("role", "guest")  # Default to guest if role not specified
                json_string = json.dumps(payload)
                data_dict_from_json = json.loads(json_string)
                user_email = data_dict_from_json["preferred_username"]
                # user_email = 'fr@superset.com'
                if user_id:
                    print("User id****", user_id)

                    # Fetch user from the database or create a new user if not exists
                    user = session.query(sm.user_model).filter_by(email=user_email).first()

                    if not user:
                        # Create a new user if not exists (this is just an example)
                        user = sm.user_model()
                        user.username = 'test2'
                        user.email = user_email
                        user.first_name = 'Test2'
                        user.last_name = 'User2'
                        user.password = 'public'  # Set a default password; this should be hashed in production
                        user.is_active = True # Check with 0 or 1
                        session.add(user)
                        session.commit()

                    # Assign roles based on the token information
                    role = session.query(sm.role_model).filter_by(name='Gamma').first()
                    print("role", role)
                    if not role:
                        # Create a new role if not exists (this is just an example)
                        role = sm.role_model(name='Gamma')
                        session.add(role)
                        session.commit()

                    # Assign role to user
                    user.roles.append(role)
                    session.commit()
                    print("user", user)
                    login_user(user, remember=False, force=True)

                    if dashboard_id:
                        return redirect(f"/superset/dashboard/17/?standalone=2&native_filters=(NATIVE_FILTER-IwP3UoITy:(__cache:(label:!('France','Romania'),validateStatus:!f,value:!('France','Romania')),extraFormData:(filters:!((col:country,op:IN,val:!('France','Romania')))),filterState:(label:!('France','Romania'),validateStatus:!f,value:!('France','Romania')),id:NATIVE_FILTER-IwP3UoITy,ownState:()),NATIVE_FILTER-u1GGvp9x5:(__cache:(label:!('LAS'),validateStatus:!f,value:!('LAS')),extraFormData:(filters:!((col:gbu,op:IN,val:!('LAS')))),filterState:(label:!('LAS'),validateStatus:!f,value:!('LAS')),id:NATIVE_FILTER-u1GGvp9x5,ownState:()),NATIVE_FILTER-NBvj62O7J:(__cache:(label:!('VTS'),validateStatus:!f,value:!('VTS')),extraFormData:(filters:!((col:bl,op:IN,val:!('VTS')))),filterState:(label:!('VTS'),validateStatus:!f,value:!('VTS')),id:NATIVE_FILTER-NBvj62O7J,ownState:()),NATIVE_FILTER-kIQUyvdyT:(__cache:(label:!('LAS/VTS-FR'),validateStatus:!f,value:!('LAS/VTS-FR')),extraFormData:(filters:!((col:cc,op:IN,val:!('LAS/VTS-FR')))),filterState:(label:!('LAS/VTS-FR'),validateStatus:!f,value:!('LAS/VTS-FR')),id:NATIVE_FILTER-kIQUyvdyT,ownState:()))")
                    return redirect(self.appbuilder.get_url_for_index)

            flash('Unable to auto login', 'warning')
            return super(CustomAuthDBView, self).login()

        except Exception as e:
            flash(f'Unable to auto login: {str(e)}', 'warning')
            return super(CustomAuthDBView, self).login()

class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView

    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)

def init_app(app):
    # Initialize JWTManager or other app-specific setups if needed
    pass

CUSTOM_SECURITY_MANAGER = CustomSecurityManager
TALISMAN_ENABLED = False
FEATURE_FLAGS = {"DASHBOARD_RBAC": True, "EMBEDDED_SUPERSET": True, "DASHBOARD_FILTERS_EXPERIMENTAL": True, "DASHBOARD_NATIVE_FILTERS_SET": True, "DASHBOARD_NATIVE_FILTERS": True, "DASHBOARD_CROSS_FILTERS": True, "ENABLE_TEMPLATE_PROCESSING": True}



# # DEFAULT CONFIGURATION
# # Licensed to the Apache Software Foundation (ASF) under one
# # or more contributor license agreements.  See the NOTICE file
# # distributed with this work for additional information
# # regarding copyright ownership.  The ASF licenses this file
# # to you under the Apache License, Version 2.0 (the
# # "License"); you may not use this file except in compliance
# # with the License.  You may obtain a copy of the License at
# #
# #   http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing,
# # software distributed under the License is distributed on an
# # "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# # KIND, either express or implied.  See the License for the
# # specific language governing permissions and limitations
# # under the License.
# #
# # This file is included in the final Docker image and SHOULD be overridden when
# # deploying the image to prod. Settings configured here are intended for use in local
# # development environments. Also note that superset_config_docker.py is imported
# # as a final step as a means to override "defaults" configured here
# #
# import logging
# import os

# from celery.schedules import crontab
# from flask_caching.backends.filesystemcache import FileSystemCache

# logger = logging.getLogger()

# DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
# DATABASE_USER = os.getenv("DATABASE_USER")
# DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
# DATABASE_HOST = os.getenv("DATABASE_HOST")
# DATABASE_PORT = os.getenv("DATABASE_PORT")
# DATABASE_DB = os.getenv("DATABASE_DB")

# EXAMPLES_USER = os.getenv("EXAMPLES_USER")
# EXAMPLES_PASSWORD = os.getenv("EXAMPLES_PASSWORD")
# EXAMPLES_HOST = os.getenv("EXAMPLES_HOST")
# EXAMPLES_PORT = os.getenv("EXAMPLES_PORT")
# EXAMPLES_DB = os.getenv("EXAMPLES_DB")

# # The SQLAlchemy connection string.
# SQLALCHEMY_DATABASE_URI = (
#     f"{DATABASE_DIALECT}://"
#     f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
#     f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
# )

# SQLALCHEMY_EXAMPLES_URI = (
#     f"{DATABASE_DIALECT}://"
#     f"{EXAMPLES_USER}:{EXAMPLES_PASSWORD}@"
#     f"{EXAMPLES_HOST}:{EXAMPLES_PORT}/{EXAMPLES_DB}"
# )

# REDIS_HOST = os.getenv("REDIS_HOST", "redis")
# REDIS_PORT = os.getenv("REDIS_PORT", "6379")
# REDIS_CELERY_DB = os.getenv("REDIS_CELERY_DB", "0")
# REDIS_RESULTS_DB = os.getenv("REDIS_RESULTS_DB", "1")

# RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")

# CACHE_CONFIG = {
#     "CACHE_TYPE": "RedisCache",
#     "CACHE_DEFAULT_TIMEOUT": 300,
#     "CACHE_KEY_PREFIX": "superset_",
#     "CACHE_REDIS_HOST": REDIS_HOST,
#     "CACHE_REDIS_PORT": REDIS_PORT,
#     "CACHE_REDIS_DB": REDIS_RESULTS_DB,
# }
# DATA_CACHE_CONFIG = CACHE_CONFIG


# class CeleryConfig:
#     broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
#     imports = ("superset.sql_lab",)
#     result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
#     worker_prefetch_multiplier = 1
#     task_acks_late = False
#     beat_schedule = {
#         "reports.scheduler": {
#             "task": "reports.scheduler",
#             "schedule": crontab(minute="*", hour="*"),
#         },
#         "reports.prune_log": {
#             "task": "reports.prune_log",
#             "schedule": crontab(minute=10, hour=0),
#         },
#     }


# CELERY_CONFIG = CeleryConfig

# FEATURE_FLAGS = {"ALERT_REPORTS": True}
# ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
# WEBDRIVER_BASEURL = "http://superset:8088/"  # When using docker compose baseurl should be http://superset_app:8088/
# # The base URL for the email report hyperlinks.
# WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL
# SQLLAB_CTAS_NO_LIMIT = True

# #
# # Optionally import superset_config_docker.py (which will have been included on
# # the PYTHONPATH) in order to allow for local settings to be overridden
# #
# try:
#     import superset_config_docker
#     from superset_config_docker import *  # noqa

#     logger.info(
#         f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
#     )
# except ImportError:
#     logger.info("Using default Docker config...")