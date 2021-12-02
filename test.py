import tkinter as tk

root = tk.Tk()
canvas = tk.Canvas(root, width=400, height=400)
canvas.pack()
tank = canvas.create_rectangle(200, 200, 250, 250, outline='dark green', fill='dark green')

OFFSETS = {'Left': (-1, 0), 'Right': (1, 0), 'Up': (0, -1), 'Down': (0, 1)}

def move(event):
    canvas.move(tank, *OFFSETS[event.keysym])

canvas.bind('<Left>', move)
canvas.bind('<Right>', move)
canvas.bind('<Up>', move)
canvas.bind('<Down>', move)
canvas.focus_set()

root.mainloop()
