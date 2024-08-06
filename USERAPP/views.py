from django.shortcuts import render, redirect
from django.http import JsonResponse
from .forms import UserSignupForm, UserSigninForm, UploadForm, HideDataForm, DecryptForm
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.shortcuts import render
import time
from django.db.models import Sum
import matplotlib.pyplot as plt
import numpy as np
import string
from matplotlib.patches import ConnectionPatch
import secrets
from Crypto.Cipher import Blowfish
from .blowfish import encryptbf, decryptbf
import matplotlib.pyplot as plt
import mpld3
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.figure import Figure
import io
import base64
from django.http import HttpResponse
import matplotlib.pyplot as plt
from matplotlib.patches import ConnectionPatch
from .aes import encrypt, decrypt
from Crypto.Random import get_random_bytes
from .models import TextEncryptionModel, HideDataModel, RequestModel
from .rsa import generate_key_pair, save_key_to_file, load_private_key_from_file, \
    save_public_key_to_file, load_public_key_from_file, encrypted, decrypted
import tempfile
import os
from .blowfish import encryptbf, decryptbf
from PIL import Image
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
from django.http import FileResponse


# templates
INDEX = "index.html"
SIGN_UP = "signup.html"
SIGN_IN = "signin.html"
USER_HOME = "home.html"
ENCRYPT_DATA = "encrypt.html"
HIDE_DATA = "hide.html"
BAR_GRAPH = "bar_graph.html"
ALGORITHM = "algorithm.html"
HIDINING_IMAGE = "hidingimage.html"
FILE_REQUESTS = "filerequests.html"
MY_DATA = "mypage.html"
VIEW_REQUESTS = "viewrequests.html"
DECRYPT_DATA = "decrypt.html"
DOWNLOAD_FILE = "download.html"
# Create your views here.


def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


def index(req):
    return render(req, INDEX)


def signin(req):
    context = {}
    context['form'] = UserSigninForm()

    if req.method == "POST":
        form = UserSigninForm(req.POST)
        if form.is_valid():
            useremail = form.cleaned_data['useremail']
            password = form.cleaned_data['password']

            userdata = User.objects.filter(email=useremail, password=password)
            print(userdata)

            if userdata is not None:
                print("Hello")
                req.session['useremail'] = useremail
                return render(req, USER_HOME)
            else:
                return render(req, SIGN_IN, context)

    return render(req, SIGN_IN, context)


def signup(req):
    context = {}
    context['form'] = UserSignupForm()
    if req.method == "POST":
        form = UserSignupForm(req.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            useremail = form.cleaned_data['useremail']
            password = form.cleaned_data['password']
            confirmpassword = form.cleaned_data['confirmpassword']
            if password == confirmpassword:
                user_check = User.objects.filter(
                    email=useremail, password=password).exists()
                if user_check:
                    return render(req, SIGN_UP, context)
                else:
                    user_data = User.objects.create(username=username,
                                                    email=useremail, password=password)
                    user_data.save()
                    return redirect("signin")
            return render(req, SIGN_UP, context)
    return render(req, SIGN_UP, context)


def encryptdata(req):
    context = {}
    context['form'] = UploadForm()
    if req.method == "POST":
        form = UploadForm(req.POST)
        if form.is_valid():
            filename = form.cleaned_data['filename']
            usertext = form.cleaned_data['usertext']
            algorithm = form.cleaned_data['algorithm']
            print(usertext, algorithm)
            if algorithm == 'RSA':
                generatedkey = generate_random_password(10)
                # Example usage in a Django view
                private_key, public_key = generate_key_pair()

                # Save the keys to files (you might want to handle paths more dynamically)
                save_key_to_file(private_key, 'private_key.pem')
                save_public_key_to_file(public_key, 'public_key.pem')

                # Load keys from files
                loaded_private_key = load_private_key_from_file(
                    'private_key.pem')
                loaded_public_key = load_public_key_from_file('public_key.pem')

                # Encrypt and Decrypt messages
                message_to_encrypt = usertext
                start_time = time.time()

                encrypted_message = encrypted(
                    message_to_encrypt, loaded_public_key)

                decrypted_message = decrypted(
                    encrypted_message, loaded_private_key)
                print(encrypted_message, decrypted_message)
                with open(f"static/RSA/{filename}", 'w') as output_file:
                    output_file.write(decrypted_message)
                end_time = time.time()
                elapsed_time = end_time - start_time
                print(elapsed_time)
                cipher_data = TextEncryptionModel(
                    useremail=req.session['useremail'], filename=filename, cipher_text=encrypted_message, algorithm=algorithm, elapsedtime=elapsed_time, key=generatedkey)
                cipher_data.save()
                return render(req, ENCRYPT_DATA, context)

            elif algorithm == 'AES':
                generatedkey = generate_random_password(10)
                key = get_random_bytes(16)  # 128-bit key for AES
                plaintext = usertext
                # Encryption
                start_time = time.time()

                nonce, tag, ciphertext = encrypt(plaintext, key)
                # Decryption
                decrypted_text = decrypt(nonce, tag, ciphertext, key)
                with open(f"static/AES/{filename}", 'w') as output_file:
                    output_file.write(decrypted_text)
                end_time = time.time()
                elapsed_time = end_time - start_time
                print(elapsed_time)
                cipher_data = TextEncryptionModel(
                    useremail=req.session['useremail'], filename=filename, cipher_text=ciphertext, algorithm=algorithm, elapsedtime=elapsed_time, key=generatedkey)
                cipher_data.save()
                return render(req, ENCRYPT_DATA, context)

            else:
                generatedkey = generate_random_password(10)
                key = get_random_bytes(16)  # 16 bytes for Blowfish
                plaintext = usertext

                # Encryption
                start_time = time.time()
                nonce, tag, ciphertext = encryptbf(plaintext, key)
                end_time = time.time()

                # Decryption
                decrypted_text = decryptbf(nonce, tag, ciphertext, key)
                elapsed_time = end_time - start_time
                with open(f"static/BLOWFISH/{filename}", 'w') as output_file:
                    output_file.write(decrypted_text)

                context = {
                    'plaintext': plaintext,
                    'encrypted_text': ciphertext,
                    'decrypted_text': decrypted_text,
                }

                cipher_data = TextEncryptionModel(
                    useremail=req.session['useremail'], filename=filename, cipher_text=ciphertext, algorithm=algorithm, elapsedtime=elapsed_time, key=generatedkey)
                cipher_data.save()
                return render(req, ENCRYPT_DATA, context)
    return render(req, ENCRYPT_DATA, context)


def performancegraph(req):
    algorithm_data = [(i.algorithm, i.elapsedtime)
                      for i in TextEncryptionModel.objects.filter(useremail=req.session['useremail'])]
    # Prepare data for the response

    labels = [(entry[0]) for entry in algorithm_data]
    print(labels)
    elapsed_times = [float(entry[1]) for entry in algorithm_data]
    print(labels, elapsed_times)
    x = np.array(labels)
    y = np.array(elapsed_times)

    plt.bar(x, y)
    plt.show()

    return render(req, BAR_GRAPH)


def hidedata(req):
    data = TextEncryptionModel.objects.filter(
        useremail=req.session['useremail'])
    context = {}
    context['form'] = HideDataForm()
    if req.method == "POST":
        form = HideDataForm(req.POST)
        if form.is_valid():
            algorithm = form.cleaned_data['algorithm']
            print(algorithm)
            all_data_files = TextEncryptionModel.objects.filter(
                useremail=req.session['useremail'], algorithm=algorithm)
            return render(req, ALGORITHM, {'algorithm': algorithm, 'all_data_files': all_data_files})
    return render(req, HIDE_DATA, {'context': context, 'data': data})


def hidingimage(request):
    if request.method == "POST":
        # Handle the case where 'useremail' is not present in the session
        user_email = request.session.get('useremail')
        if user_email is None:
            # Handle this case according to your requirements
            return render(request, 'error_page.html', {'error_message': 'User email not found in session'})

        algorithm = request.POST['algorithm']
        image_file = request.FILES['imagefiledata']
        filename = request.POST['filename']

        data = TextEncryptionModel.objects.filter(
            useremail=user_email, algorithm=algorithm, filename=filename).values_list('cipher_text', flat=True).first()

        if data:
            ciphertext = data
            imagename = image_file.name
            try:
                img = Image.open(image_file)
                binary_ciphertext = ''.join(
                    format(ord(char), '08b') for char in ciphertext)

                if len(binary_ciphertext) > img.width * img.height:
                    raise ValueError(
                        "Ciphertext is too large for the given image")

                binary_index = 0
                for i in range(img.width):
                    for j in range(img.height):
                        pixel = list(img.getpixel((i, j)))
                        for k in range(3):  # Iterate over RGB channels
                            if binary_index < len(binary_ciphertext):
                                pixel[k] = int(format(pixel[k], '08b')[
                                               :-1] + binary_ciphertext[binary_index], 2)
                                binary_index += 1
                        img.putpixel((i, j), tuple(pixel))

                output_path = f"static/stegno/{imagename}"
                img.save(output_path)
                data = HideDataModel(image=image_file,
                                     imagename=filename, ciphertext=ciphertext, algorithm=algorithm)
                data.save()
                print("Success")
            except Exception as e:
                print(f"Error: {str(e)}")

    return redirect("hidedata")


def filerequests(req):

    all_data = TextEncryptionModel.objects.all()

    return render(req, FILE_REQUESTS, {'all_data': all_data, 'useremail': req.session['useremail']})


def sendrequest(req, id):
    update_data = [(i.useremail, i.filename, i.cipher_text, i.algorithm, i.elapsedtime,
                    i.key, i.status) for i in TextEncryptionModel.objects.filter(id=id)][0]
    print(update_data)

    store_data = RequestModel(
        fileid=id,
        useremail=update_data[0],
        filename=update_data[1],
        cipher_text=update_data[2],
        algorithm=update_data[3],
        elapsedtime=update_data[4],
        key=update_data[5],
        status="success",
        requestedemail=req.session['useremail']
    )
    store_data.save()
    data = TextEncryptionModel.objects.get(id=id)
    data.status = "success"
    data.save()

    return redirect("filerequests")


def viewrequests(req):
    mydata = RequestModel.objects.filter(
        useremail=req.session['useremail'])
    return render(req, VIEW_REQUESTS, {'mydata': mydata})


def sendkey(req, id, fileid):
    print(id, fileid)

    # Fetch data from the database using get() instead of filter()
    try:
        # Assuming TextEncryptionModel has fields: key, requestedemail, filename, algorithm
        data = TextEncryptionModel.objects.get(id=fileid)
        newdata = RequestModel.objects.get(fileid=fileid)
    except TextEncryptionModel.DoesNotExist:
        # Handle the case where the object with the given ID does not exist
        return HttpResponse("File not found.")

    print(data)
    subject = "Cryptography and Steganography"
    # Use data.requestedemail instead of newdata[1]
    cont = f'Dear {newdata.requestedemail}'
    # Use data.key instead of newdata[0]
    KEY = f'fileid {fileid} \n Your Key to Decrypt the Image : {newdata.key}\n and algorithm {newdata.algorithm} '

    m2 = "Thanking you"
    m3 = "Regards"
    m4 = "Admin."

    # Create the EmailMessage object
    email = EmailMessage(subject, cont + '\n' + KEY + '\n' + m2 + '\n' +
                         m3 + '\n' + m4, settings.EMAIL_HOST_USER, [newdata.requestedemail])
    # Attach the image
    with open(f"static/{data.algorithm}/{data.filename}", "rb") as attachment:
        email.attach(data.filename, attachment.read(), "image/jpeg")

    # Send the email
    try:
        email.send(fail_silently=False)
        return redirect("viewrequests")
    except Exception as e:
        return HttpResponse(f"Error sending email: {str(e)}")


def download_file(request, decrypted_data):
    response = HttpResponse(decrypted_data.imagefile.read(),
                            content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{decrypted_data.imagefile.name}"'
    return response


def decryptdata(req):
    context = {}
    context['form'] = DecryptForm()

    if req.method == "POST":
        form = DecryptForm(req.POST, req.FILES)
        if form.is_valid():
            fileid = form.cleaned_data['fileid']
            imagefile = form.cleaned_data['imagefile']
            filename = form.cleaned_data['filename']
            algorithm = form.cleaned_data['algorithm']
            key = form.cleaned_data['key']
            imagename = imagefile.name

            data = TextEncryptionModel.objects.filter(
                id=fileid, filename=filename, algorithm=algorithm, key=key)

            if not data.exists():
                print("1234")
            else:
                img_path = os.path.join(
                    settings.BASE_DIR, 'static', 'hidedata', imagename)

                img = Image.open(img_path)

                binary_ciphertext = ""
                for i in range(img.width):
                    for j in range(img.height):
                        pixel = img.getpixel((i, j))
                        for k in range(3):  # Iterate over RGB channels
                            binary_ciphertext += format(
                                pixel[k], '08b')[-1]

                ciphertext = ''.join(chr(
                    int(binary_ciphertext[i:i+8], 2)) for i in range(0, len(binary_ciphertext), 8))

                if ciphertext != "":

                    decrypted_data = data.first()
                    f = open(f"static/{algorithm}/{filename}", 'r')
                    content = f.read()
                    print(content)
                    return render(req, DOWNLOAD_FILE, {'content': content, 'filename': filename})

    return render(req, DECRYPT_DATA, context)
