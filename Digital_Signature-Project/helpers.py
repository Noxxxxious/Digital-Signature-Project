import pygame
import tkinter
import tkinter.filedialog


def draw_text(window, rect, text, font, color=(160, 160, 160)):
    text = font.render(text, True, color)
    text_rect = text.get_rect(center=rect.center)
    window.blit(text, text_rect)


def chosen_file(extension=None):
    root = tkinter.Tk()
    root.withdraw()
    if extension:
        file_name = tkinter.filedialog.askopenfilename(parent=root, filetypes=extension)
    else:
        file_name = tkinter.filedialog.askopenfilename(parent=root)
    root.destroy()
    return file_name

#
# def chosen_sp_file():
#     root = tkinter.Tk()
#     root.withdraw()
#     key = tkinter.filedialog.askopenfilename(parent=root, filetypes=file_types)
#     root.destroy()
#     return key
