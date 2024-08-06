# views.py
from django.shortcuts import render
from .forms import HideDataForm
from PIL import Image


def hide_data(request):
    context = {}
    if request.method == 'POST':
        form = HideDataForm(request.POST, request.FILES)
        if form.is_valid():
            imagefile = request.FILES['imagefile']
            ciphertext = form.cleaned_data['ciphertext']

            try:
                img = Image.open(imagefile)
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

                output_path = "path/to/your/output_image.png"
                img.save(output_path)
                context['success_message'] = 'Ciphertext successfully hidden in the image.'
            except Exception as e:
                context['error_message'] = f"Error: {str(e)}"

    else:
        form = HideDataForm()

    context['form'] = form
    return render(request, 'hide_data.html', context)
