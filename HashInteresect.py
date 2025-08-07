# -*- coding: utf-8 -*-
"""
HashIntersect

Version: 1.0 Beta
Auteur: Vincent Chapeau
Contact : vincent.chapeau@teeltechcanada.com
Date: 04 août 2025

Description:
Utilitaire de comparaison et d'intersection pour listes de hachages de fichiers.
L'outil prend en entrée de 2 à 5 fichiers texte listant des hachages (MD5, etc.)
et retourne la liste des hachages qui sont communs à tous les fichiers.
Idéal pour l'analyse forensique (identification de fichiers système) ou la gestion de données (recherche de doublons).
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os

class MD5ComparatorApp:
    def __init__(self, root):
        """Initialise l'application et ses widgets."""
        self.root = root
        self.root.title("Comparateur de Hachages MD5")
        self.root.geometry("750x670")

        self.file_paths = [] # Liste pour stocker les StringVars des chemins de fichiers

        # --- Cadre pour la sélection des fichiers ---
        file_frame = tk.LabelFrame(root, text=" 1. Sélection des fichiers (2 minimum) ", padx=10, pady=10)
        file_frame.pack(padx=10, pady=10, fill="x")

        # Création dynamique des 5 champs de sélection
        for i in range(5):
            path_var = tk.StringVar()
            self.file_paths.append(path_var)
            
            label_text = f"Fichier MD5 n°{i+1}:"
            if i >= 2:
                label_text = f"Fichier MD5 n°{i+1} (facultatif):"

            tk.Label(file_frame, text=label_text).grid(row=i, column=0, sticky="w", pady=2)
            tk.Entry(file_frame, textvariable=path_var, width=70, state='readonly').grid(row=i, column=1, padx=5)
            # La fonction lambda est cruciale pour passer le bon index 'i' au moment du clic
            tk.Button(file_frame, text="Parcourir...", command=lambda i=i: self.select_file(i)).grid(row=i, column=2)

        # --- Bouton de comparaison ---
        tk.Button(root, text="Comparer et trouver les communs", command=self.compare_files, font=('Helvetica', 10, 'bold')).pack(pady=10)

        # --- Cadre pour les résultats ---
        result_frame = tk.LabelFrame(root, text=" 2. MD5 communs (Intersection) ", padx=10, pady=10)
        result_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.result_text = scrolledtext.ScrolledText(result_frame, width=80, height=20, wrap=tk.WORD)
        self.result_text.pack(fill="both", expand=True)
        
        # --- Bouton Sauvegarder ---
        self.save_button = tk.Button(root, text="Sauvegarder le résultat", command=self.save_results, state="disabled")
        self.save_button.pack(pady=10)


    def select_file(self, index):
        """Ouvre une boîte de dialogue pour sélectionner un fichier et met à jour le champ correspondant."""
        path = filedialog.askopenfilename(title=f"Sélectionnez le fichier MD5 n°{index+1}", filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")])
        if path:
            self.file_paths[index].set(path)

    def read_hashes_from_file(self, filepath):
        """Lit les hachages d'un fichier et les retourne en tant que set (pour supprimer les doublons)."""
        if not os.path.exists(filepath):
            return None
        
        hashes = set()
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line:
                        hashes.add(clean_line)
        except Exception as e:
            messagebox.showerror("Erreur de lecture", f"Impossible de lire le fichier {os.path.basename(filepath)}:\n{e}")
            return None
        return hashes

    def compare_files(self):
        """Fonction principale qui compare tous les fichiers fournis."""
        # Récupérer uniquement les chemins qui ont été remplis
        selected_paths = [p.get() for p in self.file_paths if p.get()]

        if len(selected_paths) < 2:
            messagebox.showwarning("Fichiers insuffisants", "Veuillez sélectionner au moins 2 fichiers à comparer.")
            return

        # Vider la zone de résultat précédente
        self.result_text.delete('1.0', tk.END)
        self.save_button.config(state="disabled")

        # Lire tous les fichiers et les stocker dans une liste de sets
        list_of_hash_sets = []
        for path in selected_paths:
            hashes = self.read_hashes_from_file(path)
            if hashes is None: # Si une erreur de lecture survient
                return
            list_of_hash_sets.append(hashes)

        # Calculer l'intersection de tous les sets fournis
        # set.intersection() peut prendre plusieurs sets comme arguments
        common_hashes = set.intersection(*list_of_hash_sets)

        if not common_hashes:
            self.result_text.insert(tk.END, "Aucun MD5 commun n'a été trouvé parmi les fichiers fournis.")
            messagebox.showinfo("Résultat", "Aucun MD5 commun n'a été trouvé.")
        else:
            # Affichage des résultats
            header = f"Comparaison de {len(selected_paths)} fichiers terminée.\n\n"
            for i, hash_set in enumerate(list_of_hash_sets):
                 header += f"Fichier {i+1}: {len(hash_set)} MD5 uniques.\n"
            header += f"\nMD5 communs (intersection) trouvés: {len(common_hashes)}\n"
            header += "----------------------------------------\n"
            
            self.result_text.insert(tk.END, header)
            
            sorted_common = sorted(list(common_hashes))
            
            self.result_text.insert(tk.END, "\n".join(sorted_common))
            self.save_button.config(state="normal")
            messagebox.showinfo("Résultat", f"{len(common_hashes)} MD5 communs ont été trouvés.")

    def save_results(self):
        """Sauvegarde le contenu de la zone de résultat dans un fichier."""
        content = self.result_text.get('1.0', tk.END).strip()
        
        if "Aucun MD5 commun" in content or not content:
            messagebox.showinfo("Information", "Il n'y a rien à sauvegarder.")
            return
            
        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")],
            title="Enregistrer les MD5 communs",
            initialfile="md5_intersection.txt"
        )

        if save_path:
            try:
                with open(save_path, 'w', encoding='utf-8') as f:
                    lines = content.splitlines()
                    start_index = 0
                    for i, line in enumerate(lines):
                        if "----------------" in line:
                            start_index = i + 1
                            break
                    
                    actual_hashes = lines[start_index:]
                    f.write("\n".join(actual_hashes))
                messagebox.showinfo("Succès", f"Résultat sauvegardé dans {save_path}")
            except Exception as e:
                messagebox.showerror("Erreur de sauvegarde", f"Impossible de sauvegarder le fichier:\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = MD5ComparatorApp(root)
    root.mainloop()