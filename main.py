from flask import Flask, render_template, request, url_for, make_response
from flask_mail import Mail, Message
import sqlite3
import hashlib
import time
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

sql=sqlite3.connect("blogs.db", check_same_thread=False)
sql.execute("Create table if not exists users (username	TEXT, password TEXT, firstName TEXT,lastName TEXT, eMail TEXT, salt Text)")
sql.commit()

app = Flask(__name__)
mail=Mail(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'buraksamp34@gmail.com'
app.config['MAIL_PASSWORD'] = '3F2C9BDF0F802B4082F159ACF6332B4C4AA9F82D68B70106AF26081E6AF28E26'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
s = URLSafeTimedSerializer('Thisisasecret!')
def sendEmail(title,recipients,message):
    msg = Message(title, sender='buraksamp34@gmail.com', recipients=[recipients])
    msg.body = message
    try:
        mail.send(msg)
        return True
    except:
        return False
def checkUsername(username):
    sonuc=list(sql.execute(f"select username from users where username='{username}'"))
    if len(sonuc)==0:
        return True
    else:
        return False


@app.route('/')
def home():
   return render_template('home.html')

@app.route('/register')
def ormliKayit():
   return render_template('register.html')

@app.route('/new-register',methods = ['POST', 'GET'])
def addrec():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        eMail = request.form['eMail']


        if username=="":
            return render_template("errormsg.html", err="Username cannot be blank")
        elif firstName=="":
            return render_template("errormsg.html", err="First Name cannot be blank")
        elif lastName=="":
            return render_template("errormsg.html", err="Last Name cannot be blank")
        elif eMail=="":
            return render_template("errormsg.html", err="E-Mail cannot be blank")
        elif password=="" or password2=="":
            return render_template("errormsg.html", err="Password cannot be blank")
        elif password!=password2:
            return render_template("errormsg.html", err="Passwords not match")

        if checkUsername(username):
            password = hashlib.sha256(password.encode('ascii')).hexdigest()
            salt = hashlib.sha256(str(time.time()).encode('ascii')).hexdigest()
            password = hashlib.sha256((password+salt).encode('ascii')).hexdigest()


            token = s.dumps(eMail, salt='email-confirm')
            link = url_for('confirm_email', token=token, _external=True)
            print(link)
            sendEmail("Burak Blog Activation Mail",eMail,f"Activation link: {link}")


            resp = make_response(render_template('register.html'))
            resp.set_cookie('usernameCookie', username)
            resp.set_cookie('passwordCookie',  password)
            resp.set_cookie('firstNameCookie', firstName)
            resp.set_cookie('lastNameCookie', lastName)
            resp.set_cookie('eMailCookie', eMail)
            resp.set_cookie('saltCookie', salt)

            return resp
        else:
            return render_template("errormsg.html", err="Username already exit")


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    username = request.cookies.get('usernameCookie')
    password = request.cookies.get('passwordCookie')
    firstName = request.cookies.get('firstNameCookie')
    lastName = request.cookies.get('lastNameCookie')
    eMail= request.cookies.get('eMailCookie')
    salt = request.cookies.get('saltCookie')
    print(username,password,firstName,lastName,eMail,salt)
    if checkUsername(username):
        pass
        #sql.execute(f"insert into users values('{username}', '{password}', '{firstName}', '{lastName}', '{eMail}', '{salt}')")
        #sql.commit()
    else:
        return render_template("errormsg.html", err="Username already exit")
    return '<h1>The token works!</h1>'



if __name__ == '__main__':
   app.run(debug = True)