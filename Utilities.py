import tkinter as tk
import tkinter.ttk as ttk 

class Utilities():
    def CreateButton(self, parent, text="", function=None, width=15) -> tk.Button:
        btn = tk.Button(parent, text=text, width=width, command=function, bg="#0917d3", fg="white", activebackground="#8aa2e2")
        return btn

    def OnComboSelect(self, *args):
        self.combo_box.selection_clear()

    def CreateComboBox(self, parent, values, width=32, state="readonly") -> ttk.Combobox:
        # Create Combobox with fixed width
        self.combo_box = ttk.Combobox(parent, values=values, width=width, state=state)
        self.combo_box.set(values[0])  # default value
        self.combo_box.bind("<<ComboboxSelected>>", self.OnComboSelect)
        return self.combo_box