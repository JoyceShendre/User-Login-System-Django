from email import message
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from user_login_sys import settings
from django.core.mail import send_mail, EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template import loader
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token

# Create your views here.


def home(request):
    return render(request, 'authentication/index.html')


def signup(request):

    if request.method == 'POST':
        #username = request.POST.get('username')
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['password1']
        pass2 = request.POST['password2']

        if User.objects.filter(username=username):
            messages.error(request, "This username is already taken")
            return redirect('home')

        if User.objects.filter(email=email):
            messages.error(request, "This email is already taken")
            return redirect('home')

        if len(username) > 10:
            messages.error(
                request, "Username is too long,it must be under 10 characters")

        if(pass1 != pass2):
            messages.error(request, "Passwords does not match")

        if not username.isalnum():
            messages.error(request, "Username must be Alphanumeric")
            return redirect('home')

        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname

        myuser.is_active = False
        myuser.save()

        messages.success(
            request, "Your account has been created.We have sent you a confirmation email,please confirm your email in order to activate your account.")

        # Welcome email

        subject = "Welcome to Django Project!"
        message = "Hello" + myuser.first_name + \
            " Please confirm your email address to verify your account."
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=False)

        # Email Address Confirmation

        current_site = get_current_site(request)
        email_subject = "Confirm your email @Django Project Login"
        message2 = loader.render_to_string('email_confirmation.html', {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)

        })
        email1 = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email1.fail_silently = False
        email1.send()

        return redirect('signin')

    return render(request, 'authentication/signup.html')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        print('uid=====>>>', uid)
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request, myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request, 'activation_failed.html')


def signin(request):

    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['password1']

        user = authenticate(username=username, password=pass1)

        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, 'authentication/index.html', {'fname': fname})
        else:
            messages.error(request, "Bad Credentials")

    return render(request, 'authentication/signin.html')


def signout(request):

    logout(request)
    messages.success(request, "Just logged out")
    return redirect('home')
