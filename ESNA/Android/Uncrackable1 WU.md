# Description

[Uncrackable1](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes/Android/Level_02) est un des 4 challenges Android développé par l'OWASP dans le cadre de son guide, [Mobile Application Security Testing Guide (MASTG)](https://github.com/OWASP/owasp-mastg). Ce challenge est dédié aux débutants cherchant a monter en compétences en pentest Android. Il met à disposition un fichier [APK](https://fr.wikipedia.org/wiki/APK_(format_de_fichier)) protège par un mot de passe nous barrant la route. L'objectif est donc de cracker ce dernier.


# Execution de l'APK

Présenté avec un fichier APK, la première chose qui parait naturel est d'exécuter ce dernier.  
Bien que possédant moi même un téléphone Android, exécuter un fichier APK de source inconnue sur son téléphone personnel n'est pas une très bonne idée. Ne possédant pas de téléphone dédié au pentest Android, je me tourne vers l'émulation.  
Possédant déjà Android Studio, je décide premièrement d'utiliser l'émulateur d'Android Studio, AVD.  
Cependant, bien qu'il soit largement possible de faire ce challenge avec cet émulateur, je me rends rapidement compte que son concurent Genymotion est bien plus simple d'utilisation et je décide de continuer avec ce dernier.

Je drag&drop l'APK dans l'émulateur, le lance et suis accueilli par un message me bloquant l'accès a l'application tant que le téléphone soit root. Il semblerait que Genymotion propose par défaut un téléphone rooté, et que cela ne plaise pas à l'application. On voit aussi une entrée demandant une phrase secrète.

![[Uncrk1RootMsg.png]]


# Analyse de l'APK

Il est temps d'analyser le contenu de l'APK.
On utilise ```apktool``` pour decompresser l'APK.
```
apktool -d UnCrackable-Level1.apk
```
Puis on lance le decompileur [```jadx```](https://github.com/skylot/jadx) pour lire le code source de l'application sous forme de code Java, plus facile à lire que le code Smali donne par apktool.

Premièrement, on cherche le point d'entré de l'application, ce dernier se trouve dans le manifeste.
![[Pasted image 20230112222614.png]]

On analyse maintenant le point d'entré.
![[Pasted image 20230112222805.png]]

On voit deux fonctions intéressantes. La première est la méthode 'a(str)' qui génère la boite de dialogue nous empêchant l'accès a l'entrée de la phrase secrète.
![[Pasted image 20230112223116.png]]

La seconde est la méthode 'verify(view)' qui se sert du retour de la méthode 'a(obj)' d'une classe 'a' pour déterminer la validité de la phrase secrète.
![[Pasted image 20230112223201.png]]

On s'intéresse donc à la méthode a.a(obj)
![[Pasted image 20230112223430.png]]

Cette dernière prend deux chaînes, se sert de la première pour générer une clé AES et déchiffrer la seconde. On sait que l'opération déchiffre grâce à là [documentation de la classe cipher](https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html). En effet le paramètre passé à la méthode init est le mode opératoire, le 2 correspondant a un déchiffrement.  
Elle retourne le résultat déchiffré.

# Exploitation

Pour exploiter cette APK afin de la cracker, j'utilise plusieurs outils, le premier étant [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb?hl=fr). Cet outil permet de contrôler le téléphone en mode développeur, que j'active en cliquant 7 fois sur le numéro de build du téléphone se trouvant dans ses paramètres.  
Cet outil permet notamment l'utilisation du dernier outil que je vais utiliser, [Frida](https://frida.re/docs/examples/android/).

La première étape est de contourner le blocage qui apparaît lorsque nous sommes root.  
Je pourrais tout simplement de pas rooter le téléphone, mais cela m'empêcherait d'utiliser Frida pour cracker la phrase secrète.  
  
Le plan d'attaque est d'utiliser Frida pour hooker les fonctions me bloquant l'accès et retrouver la phrase secrète au runtime.  
  
Je commence donc par écrire un script Python me permettant d'attacher Frida a l'APK et d'y injecter du code Java

```python
import frida
from time import sleep

device = frida.get_usb_device()
pid = device.spawn(["owasp.mstg.uncrackable1"])

sleep(1)

session = device.attach(pid)
script = session.create_script(open("s1.js").read())
script.load()

device.resume(pid)

input()
```


j'utilise ensuite Frida pour hooker la méthode a(str) qui me dérange, et la remplacer par une méthode factice.
```Java
Java.perform(function()
{
    Java.use("sg.vantagepoint.uncrackable1.MainActivity").a.implementation = function(s)
    {
         console.log("qwe");
    };
});
```

Je hook ensuite la fonction de déchiffrement pour la surcharger en affichant le résultat du déchiffrement.
```Java
Java.perform(function()
{
    Java.use("sg.vantagepoint.a.a").a.implementation = function(arr1, arr2)
    {
        const key = this.a(arr1, arr2)
        console.log(key)
        return key
    };
});
```

J'obtiens la chaîne ASCII suivante.
![[Pasted image 20230112230505.png]]
![[Pasted image 20230112230848.png]]

Voici notre phrase secrète: "I want to believe".