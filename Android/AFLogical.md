
# Fonctionnement

## Description

Application destinée à être utilisée depuis un téléphone intelligent utilisant le système d'exploitation Android. Cette application est faite pour être utilisée dans le cadre d'une extraction de données personnels mobiles contenue dans des fichiers du téléphone.

Application permettant l'extraction de données mobiles telles que:
- Historique d'appels
- Contactes
- MMS
- MMParts
- SMS

Le résultat de l'extraction est écrit dans les fichiers suivant:
- CallLog Calls.csv
- Contacts Phones.csv
- MMS.csv
- MMSParts.csv
- SMS.csv

Il n'est pas recommandé d'installer cette application si l'utilisateur n'en a pas explicitement besoin.  
Il est recommandé désinstaller l'application après utilisation.

## Implementation

### ForensicsActivity
Gère l'activité principale, soit l'IHM.

### ForensicsGatherer

Appelle la initializeContentProviders(), qui initialise les classes permettant l'extraction de données.
```java
public void initializeContentProviders() {
        this.configuredProviders = new ArrayList();
        this.configuredProviders.add(new CallLogProvider("CallLog Calls", CallLog.Calls.CONTENT_URI));
        this.configuredProviders.add(new CSVForensicsProvider("Contacts Phones", Contacts.Phones.CONTENT_URI));
        this.configuredProviders.add(new CSVForensicsProvider("MMS", Uri.parse("content://mms")));
        this.configuredProviders.add(new MmsPartsProvider("MMSParts", Uri.parse(MmsPartsProvider.CONTENT_URI)));
        this.configuredProviders.add(new CSVForensicsProvider("SMS", Uri.parse("content://sms")));
        Log.i(ForensicsGatherer.class.getName(), String.valueOf(this.configuredProviders.size()) + " providers initialized.");
    }
```

#### ForensicsProvider

Cette classe sert de parent aux classes permettant l'extraction de données.  
Elle implémente les informations minimales communes pour extraire tout type d'information personnelle Android.
```java
public ForensicsProvider(String displayName, Uri uri) {
        this.displayName = null; //Nom du fichier
        this.uri = null; // Chemin de l'objet a extraire
        this.displayName = displayName;
        this.uri = uri;
    }
```


#### CSVForensicsProvider 

Cette classe est une extension de ForensicsProvider. Elle implémente les fonctionnalités permettant la création et la modification de fichier CSV.  
Elle implémente la mise en forme des informations extraites et les écrits si possible dans un fichier CSV.  
  
La méthode process() extrait l'information contenue dans le fichier pointe par le nom donne en paramètre URI, dans un fichier csv.
```java
public void process(Context context, File forensicsDir) throws ForensicsException {
        ContentResolver resolver = context.getContentResolver();
        DebugLogger.d(TAG, "processing " + this.displayName); // Affichage de debug
        try {
            Cursor idsOnlyCursor = resolver.query(this.uri, new String[]{"_id"}, null, null, "_id ASC"); // Placement de la lecture a la premiere ligne du fichier
            if (idsOnlyCursor != null) { // Lecture ligne par ligne
                BufferedWriter writer = new BufferedWriter(new FileWriter(new File(forensicsDir, String.valueOf(this.displayName) + ".csv")), 8096); // Ecriture des donnees extraites dans le fichier csv
                idsOnlyCursor.getCount();
                queryContent(resolver, writer, true, null); // Lecture du fichier contenant les donnees a extraire
                if (writer != null) {
                    try {
                        writer.close();
                    } catch (IOException ex) {
                        Log.e(getClass().getName(), "Error message: ", ex);
                    }
                }
            } else {
                idsOnlyCursor = resolver.query(this.uri, null, null, null, null);
                if (idsOnlyCursor != null) {
                    String[] cols = idsOnlyCursor.getColumnNames();
                    throw new ForensicsException("No '_id' column found. " + cols.toString());
                }
                Log.w(TAG, "Unable to find data for " + this.displayName);
            }
            if (idsOnlyCursor != null) {
                idsOnlyCursor.close();
            }
            postProcess();
        } catch (Exception ex2) {
            Log.e(TAG, "Unexpected error in (" + this.displayName + "): ", ex2);
            throw new ForensicsException(ex2);
        }
    }
```

#### CallLogProvider

Cette classe étend CSVForensicsProvider pour formater les données extraites.
```java
protected String[] getProviderProjection() {
        String[] projection = {"_id", "number", "date", "duration", "type", "new", "name", "numbertype", "numberlabel"};
        return projection;
    }
```


# Conclusion

Cette application mobile Android collecte les données personnelles de l'utilisateur du téléphone sur laquelle elle est installée.  
Cette application peu être utilisée de manière malveillante si la cible de la collecte n'est pas consentante pour effectuer cette opération.  
Il est recommandé de n'utiliser cette application que si l'on a un réel besoin de récupération de données. L'application doit ensuite être désinstaller de l'appareil si ce dernier est utilisé de manière conventionnelle.