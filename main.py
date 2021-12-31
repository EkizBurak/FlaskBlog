from flask import Flask, render_template, request, url_for, make_response, session, redirect
from flask_mail import Mail, Message
import sqlite3
import hashlib
import time
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import os
import base64
from math import ceil


sql=sqlite3.connect("blogs.db", check_same_thread=False)
sql.execute("Create table if not exists users (username	TEXT, password TEXT, firstName TEXT,lastName TEXT, eMail TEXT, salt Text, avatar BLOB)")
sql.commit()

app = Flask(__name__)

app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'


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
    check=list(sql.execute(f"select username from users where username='{username}'"))
    if len(check)==0:
        return True
    else:
        return False

@app.route('/',methods = ['POST', 'GET'])
def home():
    page=1
    if request.method == 'POST':
        page = request.form["page"]
    blogCount=list(sql.execute("select count(*) from blogs"))[0][0]
    pageCount = ceil(blogCount/15)


    blogs=list(sql.execute(f"select blogs.username, title, desc, avatar from blogs inner join users on users.username=blogs.username where blogs.rowid<='{blogCount-15*int(page)+15}' and blogs.rowid>'{blogCount-15*int(page)}'"))
    blogs.reverse()
    for sayac,i in enumerate(blogs):
        for xsayac,x in enumerate(i):
            if xsayac==3:
                encoded_img_data = base64.b64encode(x)
                blogs[sayac]=list(blogs[sayac])
                blogs[sayac][xsayac]=encoded_img_data.decode('utf-8')

    return render_template('home.html',blogs=blogs, pageCount=pageCount, page=int(page))

@app.route('/sign-up')
def signUp():
    return render_template('signup.html')

@app.route('/new-sign-up',methods = ['POST', 'GET'])
def newSignUp():
    if request.method == 'POST':
        uploaded_file = request.files['myFileInput22']
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        eMail = request.form['eMail']
        try:
            privacyPolicy = request.form['privacyPolicy']
        except:
            return render_template("signup.html", err="Please Confirm Privacy Policy", username=username, firstName=firstName,lastName=lastName, eMail=eMail)
        if username=="":
            return render_template("signup.html", err="Username cannot be blank", username=username, firstName=firstName, lastName=lastName, eMail=eMail)
        elif firstName=="":
            return render_template("signup.html", err="First Name cannot be blank", username=username, firstName=firstName, lastName=lastName, eMail=eMail)
        elif lastName=="":
            return render_template("signup.html", err="Last Name cannot be blank", username=username, firstName=firstName, lastName=lastName, eMail=eMail)
        elif eMail=="":
            return render_template("signup.html", err="E-Mail cannot be blank", username=username, firstName=firstName, lastName=lastName, eMail=eMail)
        elif password=="" or password2=="":
            return render_template("signup.html", err="Password cannot be blank", username=username, firstName=firstName, lastName=lastName, eMail=eMail)
        elif password!=password2:
            return render_template("signup.html", err="Passwords not match", username=username, firstName=firstName, lastName=lastName, eMail=eMail)
        if uploaded_file.filename != '':
            uploaded_file.save(uploaded_file.filename)



        if checkUsername(username):
            password = hashlib.sha256(password.encode('ascii')).hexdigest()
            salt = hashlib.sha256(str(time.time()).encode('ascii')).hexdigest()
            password = hashlib.sha256((password+salt).encode('ascii')).hexdigest()


            token = s.dumps(eMail, salt='email-confirm')
            link = url_for('confirm_email', token=token, _external=True)
            print(username,link)
            sendEmail("Burak Blog Activation Mail",eMail,f"Activation link: {link}")


            resp = make_response(render_template('signup.html',err="Please Confirm Your E-Mail Address"))

            resp.set_cookie("avatar", uploaded_file.filename)
            resp.set_cookie('usernameCookie', username)
            resp.set_cookie('passwordCookie',  password)
            resp.set_cookie('firstNameCookie', firstName)
            resp.set_cookie('lastNameCookie', lastName)
            resp.set_cookie('eMailCookie', eMail)
            resp.set_cookie('saltCookie', salt)

            return resp
        else:
            return render_template("signup.html", err="Username already exit", username=username, firstName=firstName, lastName=lastName, eMail=eMail)

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'

    avatar = request.cookies.get('avatar')
    username = request.cookies.get('usernameCookie')
    password = request.cookies.get('passwordCookie')
    firstName = request.cookies.get('firstNameCookie')
    lastName = request.cookies.get('lastNameCookie')
    eMail= request.cookies.get('eMailCookie')
    salt = request.cookies.get('saltCookie')

    with open(avatar, 'rb') as file:
        blobData = file.read()
    os.remove(avatar)
    if checkUsername(username):
        sql.execute("insert into users values(?,?,?,?,?,?,?)",(username,password,firstName,lastName,eMail,salt,blobData))
        sql.commit()
    else:
        return render_template("signup.html", err="Username already exit")

    return render_template("home.html", err="delete signup cookies")

@app.route('/signIn',methods = ['POST', 'GET'])
def newSignIn():
    if request.method == 'POST':
        username = request.form['username22']
        password = request.form['password22']
        password = hashlib.sha256(password.encode('ascii')).hexdigest()
        if checkUsername(username)==False:
            salt = list(sql.execute(f"select salt from users where username='{username}'"))[0][0]
            password= hashlib.sha256(str(password+salt).encode('ascii')).hexdigest()
            check = list(sql.execute(f"select * from users where username='{username}' AND password='{password}'"))
            if len(check) == 1:
                session["user"] = username

                userData = list(sql.execute(f"select avatar from users where username='{session['user']}'"))[0]
                encoded_img_data = base64.b64encode(userData[0])
                avatar = encoded_img_data.decode('utf-8')

                return render_template("home.html", err="Create Local Storage Avatar", avatar=avatar)
            else:
                return render_template("home.html", err="Username or Password Wrong")
@app.route('/edit-profile')
def editProfile():
    userData=list(sql.execute(f"select firstName, lastName, eMail from users where username='{session['user']}'"))[0]
    return render_template("editProfile.html",firstName=userData[0],lastName=userData[1], eMail=userData[2])

@app.route('/confirm_change/<token>')
def confirm_change(token):
    firstName = request.cookies.get('firstNameCookie')
    lastName = request.cookies.get('lastNameCookie')
    eMail= request.cookies.get('eMailCookie')
    print(list(request.cookies.lists()))
    print("sadsadas",firstName,lastName,eMail)
    sql.execute(
        f"UPDATE users SET firstName = '{firstName}', lastName = '{lastName}', eMail='{eMail}' WHERE username='{session['user']}'")
    sql.commit()
    return render_template("home.html", err="delete signup cookies")
@app.route('/new-profile',methods = ['POST', 'GET'])
def newProfile():
    uploaded_file = request.files['myFileInput']
    if uploaded_file.filename != '':
        uploaded_file.save(uploaded_file.filename)
        with open(uploaded_file.filename, 'rb') as file:
            blobData = file.read()

        sql.execute("UPDATE users SET avatar=(?) WHERE username=(?)", (blobData,session['user']))
        sql.commit()


    firstName = request.form['firstName']
    lastName = request.form['lastName']
    eMail = request.form['eMail']


    resp = make_response(render_template('home.html', err="Please Confirm Your E-Mail Address"))

    resp.set_cookie('firstNameCookie', firstName)
    resp.set_cookie('lastNameCookie', lastName)
    resp.set_cookie('eMailCookie', eMail)


    token = s.dumps(eMail, salt='email-confirm')
    link = url_for('confirm_change', token=token, _external=True)
    print(link)
    sendEmail("Burak Blog Activation Mail", eMail, f"Activation link: {link}")


    return resp
@app.route('/post',methods = ['POST', 'GET'])
def post():
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        if title=="":
            return render_template("home.html", err="Title cannot be blank",desc=desc)
        elif desc=="":
            return render_template("home.html", err="Description cannot be blank",title=title)
        sql.execute("Create table if not exists blogs (username TEXT, title TEXT, desc TEXT)")
        sql.commit()
        sql.execute(f"insert into blogs values ('{session['user']}','{title}','{desc}')")
        sql.commit()
        return redirect("/")
@app.route('/logout')
def logout():
    session["user"] = None
    session["avatar"] = None
    return render_template("home.html")
if __name__ == '__main__':
   app.run(debug = True)
