import os
import dotenv

dotenv.load_dotenv()
app1 = os.environ.get('APP_USERNAME_OR_EMAIL')
pswrd = os.environ.get('APP_PASSWORD')
jwt = os.environ.get('JWT_SECRET_KEY')
print(jwt, app1,pswrd)