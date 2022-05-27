import pygame
from helpers import draw_text


class Button:
    def __init__(self, window, x, y, w, h, text, func):
        self.window = window
        self.x = x
        self.y = y
        self.w = w
        self.h = h
        self.rect = pygame.Rect((x, y, w, h))
        self.text = text
        self.font = pygame.font.SysFont("Arial", 16)
        self.func = func
        self.color = (70, 70, 70)
        self.colorHover = (60, 60, 60)
        self.hover = False

    def draw(self):
        drawing_color = self.color if not self.hover else self.colorHover
        pygame.draw.rect(self.window, drawing_color, self.rect)
        draw_text(self.window, self.rect, self.text, self.font)

    def mouse_over(self, mouse_pos):
        x, y = mouse_pos
        return self.x < x < self.x + self.w and self.y < y < self.y + self.h
