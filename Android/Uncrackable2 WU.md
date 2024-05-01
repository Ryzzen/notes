# Description

[Uncrackable2](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes/Android/Level_02) est un des 4 challenges Android développé par l'OWASP dans le cadre de son guide, [Mobile Application Security Testing Guide (MASTG)](https://github.com/OWASP/owasp-mastg). Ce challenge est dédié aux débutants cherchant a monter en compétences en pentest Android. Il met à disposition un fichier [APK](https://fr.wikipedia.org/wiki/APK_(format_de_fichier)) protège par un mot de passe nous barrant la route. L'objectif est donc de cracker ce dernier.


# Execution de l'APK

Présenté avec un fichier APK, la première chose qui parait naturel est d'exécuter ce dernier.  
Bien que possédant moi même un téléphone Android, exécuter un fichier APK de source inconnue sur son téléphone personnel n'est pas une très bonne idée. Ne possédant pas de téléphone dédié au pentest Android, je me tourne vers l'émulation.  
Possédant déjà Android Studio, je décide premièrement d'utiliser l'émulateur d'Android Studio, AVD.  
Cependant, bien qu'il soit largement possible de faire ce challenge avec cet émulateur, je me rends rapidement compte que son concurent Genymotion est bien plus simple d'utilisation et je décide de continuer avec ce dernier.

Je drag&drop l'APK dans l'émulateur, le lance et suis accueilli par un message me bloquant l'accès a l'application tant que le téléphone soit root. Il semblerait que Genymotion propose par défaut un téléphone rooté, et que cela ne plaise pas à l'application. On voit aussi une entrée demandant une phrase secrète.

![[Pasted image 20230112231227.png]]


# Analyse de l'APK

Il est temps d'analyser le contenu de l'APK.
On utilise ```apktool``` pour decompresser l'APK.
```
apktool -d UnCrackable-Level2.apk
```
Puis on lance le decompileur [```jadx```](https://github.com/skylot/jadx) pour lire le code source de l'application sous forme de code Java, plus facile à lire que le code Smali donne par apktool.

Premièrement, on cherche le point d'entré de l'application, ce dernier se trouve dans le manifeste.
![[Pasted image 20230112232156.png]]

On analyse maintenant le point d'entré.

On voit deux fonctions intéressantes. La première est la méthode 'a(str)' qui génère la boite de dialogue nous empêchant l'accès a l'entrée de la phrase secrète.
![[Pasted image 20230112232249.png]]

La seconde est la méthode 'verify(view)' qui se sert du retour de la méthode 'a(obj)' d'une classe 'a' pour déterminer la validité de la phrase secrète.
![[Pasted image 20230112232324.png]]

On s'intéresse donc à la méthode m.a(obj), qui est une variable de classe CodeCheck
![[Pasted image 20230112232441.png]]
![[Pasted image 20230112232505.png]]

On remarque que la méthode utilise pour vérifier la phrase secrète n'est pas implémentée. Pourtant, cette dernière a l'air de correctement fonctionner lorsque l'on test l'application sur l'émulateur.  
  
Où est-elle donc implémentée ?  
  
Dans la MainActivity, on note le chargement d'une libraire "foo"
![[Pasted image 20230112232713.png]]

Je recherche cette librairie dans le fichier de décompression donne par apktool.
![[Pasted image 20230112232853.png]]

On voit que la librairie est sous format .so (Shared Object), qui correspond au format de librairie dynamique de Linux. On le désassemble sous IDA. On trouve une fonction CodeCheck_bar, cela correspond à l'implémentation de notre fonction bar.
![[Pasted image 20230112233229.png]]

![[Pasted image 20230112233353.png]]

On voit un appel a strncmp, qui est une fonction comparant deux chaînes de caractères. La première chaîne est stockée dans la stack. C'est certainement notre chaîne d'entrée. La seconde en revanche, est stockée en tant que constante, c'est certainement notre phrase secrète.
![[hexIDA.png]]
![[hexIDA2.png]]

On décode cette chaîne ASCII (la chaîne étant stockée en little indian, on la retrouve à l'envers).
![[hexDecode.png]]

Et voilà notre phrase secrète: "Thanks for all the fish".


# Exploitation

Pour exploiter cette APK afin de la cracker, j'utilise plusieurs outils, le premier étant [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb?hl=fr). Cet outil permet de contrôler le téléphone en mode développeur, que j'active en cliquant 7 fois sur le numéro de build du téléphone se trouvant dans ses paramètres.  
Cet outil permet notamment l'utilisation du dernier outil que je vais utiliser, [Frida](https://frida.re/docs/examples/android/).

La première étape est de contourner le blocage qui apparaît lorsque nous sommes root.  
Je pourrais tout simplement de pas rooter le téléphone, mais je suis trop feignant pour cela.  
  
Le plan d'attaque est d'utiliser Frida pour hooker les fonctions me bloquant l'accès. 
  
Je commence donc par écrire un script Python me permettant d'attacher Frida a l'APK et d'y injecter du code Java.

```python
import frida
from time import sleep

device = frida.get_usb_device()
pid = device.spawn(["owasp.mstg.uncrackable2"])

sleep(1)

session = device.attach(pid)
script = session.create_script(open("s1.js").read())
script.load()

device.resume(pid)

input()
```


J'utilise ensuite Frida pour hooker les méthodes provoquant l'appel de la méthode qui nous bloque, et la remplacer par des méthodes retournant faux.
![[Pasted image 20230112235736.png]]
```Java
Java.perform(function()
{
    Java.use("sg.vantagepoint.a.b").a.implementation = function(bundle)
    {
        return false    
    };
});

  
Java.perform(function()
{
    Java.use("sg.vantagepoint.a.b").b.implementation = function(bundle)
    {
        return false    
    };
});

  
Java.perform(function()
{
    Java.use("sg.vantagepoint.a.b").c.implementation = function(bundle)
    {
        return false    
    };
});
```

Et on rentre la phrase secrète.