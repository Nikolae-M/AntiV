# abre o AntiV com duplo clique (sem janela de console)
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from antiv.gui import main
    main()
except Exception as exc:  # pythonw nao mostra erros: exibe numa janela
    import tkinter
    from tkinter import messagebox
    root = tkinter.Tk()
    root.withdraw()
    messagebox.showerror(
        "AntiV", f"Nao foi possivel iniciar:\n{exc}\n\n"
                  "Verifique se rodou: pip install -r requirements.txt")
