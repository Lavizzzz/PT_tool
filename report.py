import json
import argparse

# Configurazione degli argomenti della riga di comando
parser = argparse.ArgumentParser(description="Genera un report LaTeX da un file JSON di Vulnrepo.")
parser.add_argument("-i", "--input", required=True, help="Il percorso del file JSON di input.")
parser.add_argument("-o", "--output", default="Report.tex", help="Il percorso del file LaTeX di output (opzionale).")
args = parser.parse_args()

# Aggiungi estensione .tex al file output se non presente
if not args.output.endswith(".tex"):
    args.output += ".tex"

# Funzione per leggere il file JSON
with open(args.input, encoding='utf-8') as f:
    data = json.load(f)

# Conta le vulnerabilità in base alla gravità
severity_count = {
    'Critical': 0,
    'High': 0,
    'Medium': 0,
    'Low': 0,
    'Info': 0
}

# Funzione per determinare il colore del box in base alla gravità e per incrementare i contatori delle vulns
def get_severity_info(severity):
    if severity == 'Critical':
        severity_count['Critical'] += 1
        return 'red!5!white', 'red!75!black'
    elif severity == 'High':
        severity_count['High'] += 1
        return 'orange!5!white', 'orange!75!black'
    elif severity == 'Medium':
        severity_count['Medium'] += 1
        return 'yellow!5!white', 'yellow!75!black'
    elif severity == 'Low':
        severity_count['Low'] += 1
        return 'green!5!white', 'green!75!black'
    elif severity == 'Info':
        severity_count['Info'] += 1
        return 'blue!5!white', 'blue!75!black'
    else:
        return 'gray!5!white', 'gray!75!black'  # Default per gravità sconosciuta

# Funzione escape dei caratteri speciali in LaTeX
def escape_latex_special_chars(text):
    special_chars = {
        '_': r'\_',  
        '&': r'\&',
        '%': r'\%',
        '$': r'\$',
        '#': r'\#',
        '{': r'\{',
        '}': r'\}'
    }
    for char, escaped_char in special_chars.items():
        text = text.replace(char, escaped_char)
    return text

# Leggere il report_name e report_scope dal file JSON
report_name = escape_latex_special_chars(data.get('report_name', 'Pentest Report'))
report_scope = escape_latex_special_chars(data.get('report_scope', 'N/A'))

# Template LaTeX 
latex_report = r"""
\documentclass{article}
\usepackage[utf8]{inputenc} % Supporto per caratteri accentati
\usepackage{geometry}
\usepackage{titlesec}
\usepackage{tcolorbox} % Per i riquadri di gravità
\usepackage{hyperref} % Per i collegamenti ipertestuali
\usepackage{pgf-pie} % Per il grafico a torta
\geometry{a4paper, margin=1in}

% Formattazione dei titoli
\titleformat{\section}
  {\normalfont\Large\bfseries} 
  {}{0pt}{}
\title{""" + report_name + r"""}
\author{Generato da Vulnrepo}
\date{\today}

\begin{document}
\maketitle
\tableofcontents
\newpage

% Sezione Scope
\section{Scope}
\noindent
""" + report_scope + r"""

% Sezione Statistics and Risk con grafico a torta
\section{Statistics and Risk}
\noindent
In questa sezione viene calcolato il rischio basato sulle vulnerabilità trovate.

\begin{center}
\begin{tikzpicture}
\pie[
    sum=auto, % Disattiva la modalità percentuale
    text=legend,
    radius=3, % Dimensione del grafico
    color={red, orange, yellow, green, blue}
]{
PIE_DATA
}
\end{tikzpicture}
\end{center}

% Sezione Issues
\section{Issues}
\noindent
Sezione contenente i problemi riscontrati.
""" 

# Estrarre informazioni dal JSON e formattare ogni vulnerabilità
for vuln in data.get('report_vulns', []):
    # Escapare i caratteri speciali nel titolo
    title = escape_latex_special_chars(vuln.get('title', 'N/A'))
    description = escape_latex_special_chars(vuln.get('desc', 'N/A'))  # Anche la descrizione potrebbe avere caratteri speciali
    severity = vuln.get('severity', 'N/A')
    poc = escape_latex_special_chars(vuln.get('poc', 'N/A'))  # Escapare anche la PoC
    references = vuln.get('ref', 'N/A')
    date = vuln.get('date', 'N/A')  # Aggiungere la data dal JSON
    status = vuln.get('status', 'Open (Waiting for review)')  # Aggiungere lo status

    # Ottenere i colori in base alla gravità e aggiornare i conteggi
    colback, colframe = get_severity_info(severity)
    
    # Creare una stringa con i riferimenti formattati come link ipertestuali
    formatted_references = ""
    if references != 'N/A':
        refs = references.split('\n')  # Assumendo che i riferimenti siano separati da nuove righe
        for ref in refs:
            ref = ref.strip()  # Rimuove eventuali spazi bianchi prima e dopo il riferimento
            if ref:  # Controlla che il riferimento non sia vuoto
                ref = escape_latex_special_chars(ref)  # Escapare caratteri speciali nei riferimenti
                formatted_references += f"\\href{{{ref}}}{{{ref}}}\\\\ \n"  # Aggiungere una riga per ogni link

    # Aggiungere una sezione per ogni vulnerabilità
    latex_report += f"""
    \\subsection{{{title}}}
    \\noindent
    \\begin{{tcolorbox}}[colback={colback}, colframe={colframe}, title={severity}]
    \\textbf{{Gravità:}} {severity}
    \\end{{tcolorbox}}

    \\textbf{{Descrizione:}} \\ 
    {description} \\\\

    \\textbf{{Prova di concetto (PoC):}} \\ 
    {poc} \\\\

    \\textbf{{Riferimenti:}} \\ 
    {formatted_references} \\\\

    \\textbf{{Data:}} {date} \\ 
    \\textbf{{Stato:}} {status} \\ 
    """
    
# Usare i numeri delle vulnerabilità invece delle percentuali per il grafico a torta
critical_count = severity_count['Critical']
high_count = severity_count['High']
medium_count = severity_count['Medium']
low_count = severity_count['Low']
info_count = severity_count['Info']

# Creare i dati del grafico a torta dinamicamente, saltando i conteggi pari a 0
pie_data = []
if critical_count > 0:
    pie_data.append(f"{critical_count}/Critical")
if high_count > 0:
    pie_data.append(f"{high_count}/High")
if medium_count > 0:
    pie_data.append(f"{medium_count}/Medium")
if low_count > 0:
    pie_data.append(f"{low_count}/Low")
if info_count > 0:
    pie_data.append(f"{info_count}/Info")

# Unire i dati del grafico a torta
pie_data_str = ', '.join(pie_data)

# Sostituire i dati del grafico a torta nel template LaTeX
latex_report = latex_report.replace("PIE_DATA", pie_data_str)

# Chiudere il documento LaTeX
latex_report += "\\end{document}"

# Salvare il report LaTeX in un file .tex
with open(args.output, 'w', encoding='utf-8') as f:
    f.write(latex_report)

print(f"Report LaTeX generato con successo e salvato come {args.output}!")