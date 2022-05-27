import pygame
from helpers import draw_text


class Textbox:
    def __init__(self, window, x, y, w, h):
        self.window = window
        self.x = x
        self.y = y
        self.w = w
        self.h = h
        self.rect = pygame.Rect((x, y, w, h))
        self.text = ""
        self.active = False
        self.font = pygame.font.SysFont("Arial", 16)
        self.color = (70, 70, 70)
        self.colorActive = (60, 60, 60)

    def draw(self):
        drawingColor = self.color if not self.active else self.colorActive
        pygame.draw.rect(self.window, drawingColor, self.rect)
        draw_text(self.window, self.rect, self.text, self.font)

    def mouse_over(self, mouse_pos):
        x, y = mouse_pos
        return self.x < x < self.x + self.w and self.y < y < self.y + self.h
