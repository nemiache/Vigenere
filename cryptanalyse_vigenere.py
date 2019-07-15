# Cryptanalyse du chiffre de Vigenere

import sys, getopt, string, math
from math import sqrt

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]


# Chiffrement César
def chiffre_cesar(txt, key):
    """
    chiffrememt de Cesar
    pour chaque caractere de la chaine txt, on ajoute la valeur de key
    et on calcule le modulo
    """ 
    cle = int(key)
    res = ""
    for i in range(len(txt)):
        tmp = ord(txt[i])%ord('A')
        tmp = (tmp+cle)%26
        res += chr(tmp+ord('A'))
    return res

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    dechiffrement de Cesar
    pour chaque caractere de la chaine txt, on soustrait la valeur de key
    et on calcule le modulo
    """
    cle = int(key)
    res = ""
    for i in range(len(txt)):
        tmp = ord(txt[i] )%ord('A')
        tmp = (tmp-cle+26)%26
        res += chr(tmp + ord('A'))
    return res

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    chiffrement de Vigenere
    pour chaque caractere de la chaine txt, on ajoute la valeur de key[i]
    et on calcule le modulo
    """
    res = ""
    for i in range(len(txt)):
        tmp = ord(txt[i])%ord("A")
        tmp = (tmp + key[i%len(key)])%26
        res += chr(tmp+ord('A'))
    return res

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    dechiffrement de Vigenere
    pour chaque caractere de la chaine txt, on soustrait la valeur de key[i]
    et on calcule le modulo
    """
    res = ""
    for i in range(len(txt)):
        tmp = ord(txt[i])%ord("A")
        tmp = (tmp-key[i%len(key)]+26)%26
        res += chr(tmp+ord('A'))
    return res

# Analyse de fréquences
def freq(txt):
    """
    analyse des frequences
    on construit un tableau telque pour chaque caractere, on associe une case
    suivant l ordre aphabetique 0-->A, 1-->B, pour chaque caractere du texte, 
    on incremente la case associee
    """
    hist=[0.0]*len(alphabet)
    for lettre in txt:
        tmp = ord(lettre.upper())%ord('A')
        hist[tmp]+=1
    return hist
# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    renvoie l indice dans l alphabet de la lettre la plus frequente d un texte
    on recupere le tableau des frequences, apres, on recupere le maximum, et a 
    partir du maximum, on recupere sa position
    """
    return freq(txt).index(max(freq(txt)))

# indice de coïncidence
def indice_coincidence(hist):
    """
    indice de coincidence
    on calcule la taille totale de la chaine (la somme des frequences) puis, 
    d apres l indice de coicidences par la proposition donnee dans le sujet
    """
    res = 0.0
    for i in range(len(hist)):
        res += (hist[i]*1.0*(hist[i]-1))/(sum(hist)*1.0*(sum(hist)-1))
    return res

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    recherche de la longueur de la cle
    On construit nos colonnes de taille 1 jusqu a 20 , On calcule l indice 
    de coincidence de chaque colonne, et si  la moyenne est bien superieure 
    a 0.06 on renvoie la taille calculee, si on trouve pas on renvoie -1
    """
    for i in range(20):
        l = list()
        for j in range(i+1):
            l.append(cipher[j:len(cipher):i+1])
        indice = 0
        for colonne in l:
            indice += indice_coincidence(freq(colonne))
        if indice/((i+1)*1.0) > 0.06:
            return i+1
    return -1
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    Renvoie le tableau des decalages probables etant donne la longueur de la 
    cle en utilisant la lettre la plus frequente de chaque colonne
    """
    dec=[0]*key_length
    colonne = list()
    for j in range(key_length):
        colonne.append(cipher[j:len(cipher):key_length])
    for i in range(len(colonne)):
        dec[i] = (lettre_freq_max(colonne[i])-(ord('E')%ord('A')))%26
        
    return dec

# Cryptanalyse V1 avec décalages par frequence max
# le nombre de texte dechiffre est 18/100, 
# ca est du a la taille du texte
def cryptanalyse_v1(cipher):
    """
    cryptanalyse V1 avec decalages par frequence max
    on calcule la clef par la fonction clef_par_decalages et on applique 
    l algorithme de vigenere
    """
    key_size = longueur_clef(cipher)
    key = clef_par_decalages(cipher,key_size)
    return dechiffre_vigenere(cipher,key)


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    indice de coincidence mutuelle avec decalage
    """
    totale = sum(h1)*sum(h2)
    res = 0.0
    for i in range(len(h1)):
        res += (h1[i]*h2[(i+d)%26]*1.0)/totale
    return res

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Renvoie le tableau des decalages probables etant donne la longueur
    de la cle en comparant l indice de decalage mutuelle par rapport 
    a la premiere colonne
    """
    dec=[0]*key_length
    
    l = list()
    for j in range(key_length):
        l.append(cipher[j:len(cipher):key_length])
        
    for c in l[1:]:
        maximum = 0
        for i in range(26):
            res = indice_coincidence_mutuelle(freq(l[0]),freq(c),i)
            if res > maximum:
                dec[l.index(c)] = i
                maximum = res
    return dec

# Cryptanalyse V2 avec décalages par ICM
# le nombre de texte dechiffre est 43/100
# les textes ne sont pas grands, donc l 
# indice de coincidence mutuelle n est pas 
# exacte (ou juste)
def cryptanalyse_v2(cipher):
    """
    Cryptanalyse V2 avec decalages par ICM
    """
    l = list()
    key_length = longueur_clef(cipher)
    dec= tableau_decalages_ICM(cipher,key_length)

    for j in range(key_length):
        l.append(cipher[j:len(cipher):key_length])
    
    for i in range(len(l)):
        l[i] = dechiffre_cesar(l[i],dec[i])
    
    
    text = ""
    for i in range(len(l[0])):
        for colonne in l:
            if i < len(colonne):
                text+=colonne[i]
    decalage = (lettre_freq_max(text)-(ord('E')%ord('A')))%26
    text = dechiffre_cesar(text,decalage)

    return text


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    Prend deux listes de même taille et
    calcule la correlation lineaire de Pearson
    """
    # si les deux n ont pas la meme taille, on renvoie -1
    if len(L2) != len(L1):
        return -1
    
    cor = 0.0
    d1 = 0.0
    d2 = 0.0
    x_barre = sum(L1)/len(L1)
    y_barre = sum(L2)/len(L2)

    for i in range(len(L2)):
        cor += (L1[i] - x_barre) * (L2[i] - y_barre)
        d1 += (L1[i]-x_barre)*(L1[i]-x_barre)
        d2 += (L2[i]-y_barre)*(L2[i]-y_barre)
        
    return  (cor*1.0)/(sqrt(d1*d2))

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    Renvoie la meilleur clé possible par correlation
    étant donné une longueur de clé fixée
    """
    # on remplit le tableau des frequences freq_FR
    # j ai ajoute un fichier germinal.txt sur le serveur
    # dans le dossier data
    fichier = open("data/germinal.txt","r").read()
    freq_FR = freq(fichier)
    for i in range(len(freq_FR)):
        freq_FR[i] = freq_FR[i]/(1.0*len(fichier))
    
    
    key=[0]*key_length
    score = 0.0
    scores = [-1.0]*key_length
    l = list()
    for j in range(key_length):
        l.append(cipher[j:len(cipher):key_length])
    for i in range(key_length):
        for j in range(26):
            score_temp = correlation(freq(dechiffre_cesar(l[i],j)),freq_FR)
            if score_temp > scores[i]:
                scores[i] = score_temp
                key[i]    = j
    if len(scores) > 0:
        score = sum(scores)/(len(scores)*1.0)
    return (score, key)

# Cryptanalyse V3 avec correlations
# le nombre de texte dechiffre est 94/100
# la correlation n est pas juste 
def cryptanalyse_v3(cipher):
    """
    Cryptanalyse V3 avec correlations
    """
    score = -1.0
    key   = 0
    for i in range(20):
        score_temp,key_temp = clef_correlations(cipher,i)
        if score_temp > score:
            score = score_temp
            key   = key_temp

    text = dechiffre_vigenere(cipher,key)
    return text



# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
