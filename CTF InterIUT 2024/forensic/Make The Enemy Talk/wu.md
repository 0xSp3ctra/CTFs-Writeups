# Make the Enemy Talk [1/2]

## Intro

Pour ce chall de forensic, on nous fournit un zip contenant un fichier de dump mémoire volatile `memory.raw`, et notre but est de récupérer des informations telles que le nom de la machine, de l'utilisateur et son mot de passe de session.

```bash
 # ls
dump.zip
# unzip dump.zip
Archive:  dump.zip
  inflating: memory.raw              
  inflating: __MACOSX/._memory.raw   
# file memory.raw                                                 
memory.raw: data
```

## Récupération des informations de la machine

C'est parti, on lance notre conteneur exegol qui contient les versions 2 et 3 de [Volatility](https://github.com/volatilityfoundation/volatility), un framework d'analyse mémoire contenant beaucoup de plugins qui vont énormément nous aider pendant notre investigation. J'ai l'habitude d'utiliser la version 2 de volatility mais certains de ses plugins ne sortaient pas d'informations, on va donc utiliser la version 3.

Le nom de la machine et de l'utilisateur sont les infos les plus simples à récupérer, on peut le faire avec le plugin `envars` qui va lister les variables d'environnement.

On peut ensuite filtrer les champs `COMPUTERNAME` et `USERNAME` : 

```bash
# vol3 -f memory.raw windows.envars | grep -i "username\|computername" | sort
1000ressmsedge.exe	0x13bd34039f0canCOMPUTERNAMEd   DESKTOP-HLMQ06N      
1000	msedge.exe	0x13bd34039f0	USERNAME	Mika
```

On obtient `DESKTOP-HLMQ06N` pour le nom de la machine et `Mika` pour l'username (étonnament, c'est le prénom du chall-maker).

## Récupération du mot de passe de session

Il est maintenant temps d'utiliser la puissance des plugins de volatility. Pour récupérer le mot de passe d'une session windows, la manière la plus simple est de récupérer ses hash NT et LM, on peut utiliser pour cela le plugin `hashdump` : 

```bash
# vol3 -f memory.raw windows.hashdump         
Volatility 3 Framework 2.5.0
Progress:  100.00		PDB scanning finished                        
User	rid	lmhash	nthash

Administrateur	500	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
Invité	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount	503	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount	504	aad3b435b51404eeaad3b435b51404ee	ae9083968813556c64aaddb066cc1ce4
Mika	1001	aad3b435b51404eeaad3b435b51404ee	0df5244b85806f3154907a58d7765f91
```

On copie le hash NT de Mika et on se rend sur https://crackstation.net/ pour voir si le hash est connu.

![alt text](../Make%20The%20Enemy%20Talk/img/image.png)

C'est le cas, on a donc le flag `interiut{DESKTOP-HLMQ06N:Mika:dev}`


# Make the Enemy Talk [2/2]

## Intro

Pour cette 2e partie, le but était de révéler les derniers secrets de la capture mémoire, on n'a pas plus de précisions sur les évidences à collecter, on va donc fouiller !

## Recherche

La première chose à faire lorsqu'on investigue avec un dump mémoire est de lister les processus, pour cela on peut utiliser les plugins `pslist`, `psscan`, `pstree`...

```bash
# vol3 -f memory.raw windows.pstree
Volatility 3 Framework 2.5.0
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime

4	0	System	0xd60482c77080	129	-	N/A	False	2024-05-14 06:36:01.000000 	N/A
* 352	4	smss.exe	0xd60483959040	3	-	N/A	False	2024-05-14 06:36:01.000000 	N/A
* 92	4	Registry	0xd60482da7040	4	-	N/A	False	2024-05-14 06:35:59.000000 	N/A
* 1400	4	MemCompression	0xd60487fd1080	14	-	N/A	False	2024-05-14 06:36:06.000000 	N/A
452	444	csrss.exe	0xd60487bb0080	11	-	0	False	2024-05-14 06:36:04.000000 	N/A
528	444	wininit.exe	0xd604889cf080	5	-	0	False	2024-05-14 06:36:05.000000 	N/A
* 668	528	lsass.exe	0xd60487cb00c0	10	-	0	False	2024-05-14 06:36:05.000000 	N/A
* 636	528	services.exe	0xd60487ca20c0	8	-	0	False	2024-05-14 06:36:05.000000 	N/A
** 1664	636	svchost.exe	0xd60488543080	8	-	0	False	2024-05-14 06:36:06.000000 	N/A
** 3456	636	SearchIndexer.	0xd60488eeb280	18	-	0	False	2024-05-14 06:36:16.000000 	N/A
** 900	636	svchost.exe	0xd604880c5300	17	-	0	False	2024-05-14 06:36:05.000000 	N/A
** 3460	636	SecurityHealth	0xd6048a3a40c0	14	-	0	False	2024-05-14 06:36:34.000000 	N/A
** 1292	636	svchost.exe	0xd604885b1300	23	-	0	False	2024-05-14 06:36:05.000000 	N/A
** 1804	636	spoolsv.exe	0xd604887980c0	12	-	0	False	2024-05-14 06:36:06.000000 	N/A
** 788	636	svchost.exe	0xd604882c6280	21	-	0	False	2024-05-14 06:36:05.000000 	N/A
*** 2688	788	dllhost.exe	0xd60489170080	7	-	0	False	2024-05-14 06:36:09.000000 	N/A
*** 4992	788	RuntimeBroker.	0xd60488481080	8	-	1	False	2024-05-14 06:36:25.000000 	N/A
*** 3908	788	SearchApp.exe	0xd60488e75080	39	-	1	False	2024-05-14 06:36:15.000000 	N/A
*** 5948	788	ApplicationFra	0xd60488feb080	11	-	1	False	2024-05-14 06:36:58.000000 	N/A
*** 5288	788	dllhost.exe	0xd60487b9f080	14	-	1	False	2024-05-14 06:36:59.000000 	N/A
*** 3004	788	RuntimeBroker.	0xd60488a6e080	11	-	1	False	2024-05-14 06:36:16.000000 	N/A
*** 3596	788	TiWorker.exe	0xd60489018080	6	-	0	False	2024-05-14 06:36:14.000000 	N/A
*** 3312	788	dllhost.exe	0xd6048927f080	10	-	1	False	2024-05-14 06:36:13.000000 	N/A
*** 3668	788	RuntimeBroker.	0xd60489014080	7	-	1	False	2024-05-14 06:36:15.000000 	N/A
*** 3860	788	WmiPrvSE.exe	0xd60488e7c2c0	9	-	0	False	2024-05-14 06:36:15.000000 	N/A
*** 5108	788	smartscreen.ex	0xd60488fea080	11	-	1	False	2024-05-14 06:36:29.000000 	N/A
*** 5940	788	SystemSettings	0xd6048a42c340	17	-	1	False	2024-05-14 06:36:58.000000 	N/A
*** 5564	788	UserOOBEBroker	0xd60488b4e080	4	-	1	False	2024-05-14 06:37:01.000000 	N/A
*** 3516	788	StartMenuExper	0xd604892f3080	41	-	1	False	2024-05-14 06:36:14.000000 	N/A

```

A première vue, rien de bien spécial, les processus présents sont les processus de base de Windows, mais lorsqu'on descend en bas de l'output de notre commande, un processus intéressant apparaît :

```bash
** 2820	2640	explorer.exe	0xd6048932a080	69	-	1	False	2024-05-14 06:36:11.000000 	N/A
*** 4376	2820	DumpIt.exe	0xd6048a26d080	3	-	1	True	2024-05-14 06:37:28.000000 	N/A
**** 2484	4376	conhost.exe	0xd60488b48080	6	-	1	False	2024-05-14 06:37:30.000000 	N/A
*** 5844	2820	[KeePass.exe]	0xd60488fd0080	12	-	1	False	2024-05-14 06:36:51.000000 	N/A     # here ;)
*** 1164	2820	SecurityHealth	0xd60488166080	4	-	1	False	2024-05-14 06:36:34.000000 	N/A
*** 4148	2820	msedge.exe	0xd6048a3ad2c0	57	-	1	False	2024-05-14 06:36:35.000000 	N/A
**** 1000	4148	msedge.exe	0xd6048a42d080	17	-	1	False	2024-05-14 06:36:36.000000 	N/A
**** 4772	4148	msedge.exe	0xd6048a455080	8	-	1	False	2024-05-14 06:36:36.000000 	N/A
**** 4116	4148	msedge.exe	0xd6048a38f340	8	-	1	False	2024-05-14 06:36:35.000000 	N/A
**** 1020	4148	msedge.exe	0xd6048a42f080	19	-	1	False	2024-05-14 06:36:36.000000 	N/A
```

Il s'agit de `Keepass.exe`, un gestionnaire de mot de passe. Si la version de Keepass qui tourne sur la machine est inférieure à `2.54`, il peut être touché par la [CVE-2023-32784](https://nvd.nist.gov/vuln/detail/cve-2023-32784), qui ne permet rien de plus que de récupérer le master password en clair.

Un plugin de volatility3 va nous être utile pour tester cela, [windows.keepass](https://github.com/forensicxlab/volatility3_plugins/blob/main/keepass.py). Tentons de récupérer le master password de la database.

```bash
# vol3 -f memory.raw windows.keepass --pid 5844
Volatility 3 Framework 2.7.1
Progress:  100.00		PDB scanning finished                                                                                             
Offset	Size	Constructed_Password

0x2c9f000	0x1000	u
0x2ca0000	0x1000	ud
0x2ca1000	0x1000	udi
0x2ca1000	0x1000	udi,
0x2ca2000	0x1000	udi, 
0x2ca3000	0x1000	udi, v
<SNIP>
0x2cbb000	0x1000	udi, vide, tace, si vis vivere in pac
0x2cbc000	0x1000	udi, vide, tace, si vis vivere in pace
0x7ff9f954e000	0x1000	udi, vide, tace, si vis vivere in pace
0x7ffa1abf5000	0x1000	{u,&}di, vide, tace, si vis vivere in pace
0x8a8757c65000	0x1000	{u,a,\#}di, vide, tace, si vis vivere in pace
```

Les 2 premiers caractères du master password n'étant pas stockés dans la mémoire, le script a tenté de les bruteforce et nous propose les caractères `u` et `a`. Avec une rapide recherche google, on trouve la citation `audi, vide, tace, si vis vivere in pace`.

Le master password étant trouvé, il ne nous reste plus qu'à dump la database keepass pour l'ouvrir, commençons par la chercher avec le plugin `filescan` : 

```bash
# vol3 -f memory.raw windows.filescan | grep -E "*.kdbx"
0xd60487673700.0\Users\Mika\Documents\Database.kdbx	216
```

Parfait, nous avons trouvé le fichier ainsi que son adresse virtuelle `0xd60487673700` qui va nous permettre de récupérer le fichier :

```bash
# vol3 -f memory.raw windows.dumpfiles --virtaddr 0xd60487673700
Volatility 3 Framework 2.5.0
Progress:  100.00		PDB scanning finished                        
Cache	FileObject	FileName	Result

DataSectionObject	0xd60487673700	Database.kdbx	Error dumping file
# ls
dump  dump.zip  file.0xd60487673700.0xd60487f9f910.DataSectionObject.Database.kdbx.dat  __MACOSX  memory.raw  volatility3  wu.txt
# file file.0xd60487673700.0xd60487f9f910.DataSectionObject.Database.kdbx.dat 
file.0xd60487673700.0xd60487f9f910.DataSectionObject.Database.kdbx.dat: Keepass password database 2.x KDBX
```
(ne pas tenir en compte du message `Error dumping file`)

Essayons d'ouvrir la database avec le mot de passe retrouvé :

![alt text](/CTF%20InterIUT%202024/forensic/Make%20The%20Enemy%20Talk/img/image2.png)

![alt text](/CTF%20InterIUT%202024/forensic/Make%20The%20Enemy%20Talk/img/image3.png)

Le flag est : `interiut{UpD4t3_Ur_K33P@ss<3)`