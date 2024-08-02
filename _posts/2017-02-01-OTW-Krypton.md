---
layout: post
title: OverTheWire Krypton
date: 2017-02-01
tags: [OverTheWire]
---

# Level 0

>   Welcome to Krypton! The first level is easy. The following string encodes the password using Base64:
>
>   ```
>   S1JZUFRPTklTR1JFQVQ=
>   ```
>
>   Use this password to log in to krypton.labs.overthewire.org with username krypton1 using SSH on port 2231. You can find the files for other levels in /krypton/
>

```bash
shiro@SHIRO:/mnt/c/Users/User$ echo "S1JZUFRPTklTR1JFQVQ=" | base64 -d
KRYPTONISGREAT
```

# Level 1

>   The password for level 2 is in the file ‘krypton2’. It is ‘encrypted’ using a simple rotation. It is also in non-standard ciphertext format. When using alpha characters for cipher text it is normal to group the letters into 5 letter clusters, regardless of word boundaries. This helps obfuscate any patterns. This file has kept the plain text word boundaries and carried them to the cipher text. Enjoy!
>

```bash
sshpass -p KRYPTONISGREAT ssh krypton1@krypton.labs.overthewire.org -p 2222
```

```bash
krypton1@krypton:~$ find / -type f -name krypton2
...
find: `/tmp': Permission denied
/etc/krypton_pass/krypton2
...
find: `/root': Permission denied
/krypton/krypton1/krypton2
krypton1@krypton:~$ cd /krypton/krypton1
krypton1@krypton:/krypton/krypton1$ ls -la
total 16
drwxr-xr-x 2 root     root     4096 Nov  4  2019 .
drwxr-xr-x 8 root     root     4096 Nov  4  2019 ..
-rw-r----- 1 krypton1 krypton1  882 Nov  4  2019 README
-rw-r----- 1 krypton1 krypton1   26 Nov  4  2019 krypton2
krypton1@krypton:/krypton/krypton1$ cat README
Welcome to Krypton!

This game is intended to give hands on experience with cryptography
and cryptanalysis.  The levels progress from classic ciphers, to modern,
easy to harder.

Although there are excellent public tools, like cryptool,to perform
the simple analysis, we strongly encourage you to try and do these
without them for now.  We will use them in later excercises.

** Please try these levels without cryptool first **


The first level is easy.  The password for level 2 is in the file
'krypton2'.  It is 'encrypted' using a simple rotation called ROT13.
It is also in non-standard ciphertext format.  When using alpha characters for
cipher text it is normal to group the letters into 5 letter clusters,
regardless of word boundaries.  This helps obfuscate any patterns.

This file has kept the plain text word boundaries and carried them to
the cipher text.

Enjoy!
krypton1@krypton:/krypton/krypton1$ cat krypton2
YRIRY GJB CNFFJBEQ EBGGRA
krypton1@krypton:/krypton/krypton1$ cat krypton2 | tr 'A-Za-z' 'N-ZA-Mn-za-m'
LEVEL TWO PASSWORD ROTTEN
```

| Plaintext  | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`     |
| ---------- | ---------------------------------------------------------- |
| **Cipher** | **`NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm`** |

# Level 2

>   ROT13 is a simple substitution cipher.
>
>   Substitution ciphers are a simple replacement algorithm. In this example of a substitution cipher, we will explore a ‘monoalphebetic’ cipher. Monoalphebetic means, literally, “one alphabet” and you will see why.
>
>   This level contains an old form of cipher called a ‘Caesar Cipher’. A Caesar cipher shifts the alphabet by a set number. For example:
>
>   ```
>   plain:  a b c d e f g h i j k ...
>   cipher: G H I J K L M N O P Q ...
>   ```
>
>   In this example, the letter ‘a’ in plaintext is replaced by a ‘G’ in the ciphertext so, for example, the plaintext ‘bad’ becomes ‘HGJ’ in ciphertext.
>
>   The password for level 3 is in the file krypton3. It is in 5 letter group ciphertext. It is encrypted with a Caesar Cipher. Without any further information, this cipher text may be difficult to break. You do not have direct access to the key, however you do have access to a program that will encrypt anything you wish to give it using the key. If you think logically, this is completely easy.
>
>   One shot can solve it!
>
>   Have fun.
>
>   Additional Information:
>
>   The `encrypt` binary will look for the keyfile in your current working directory. Therefore, it might be best to create a working direcory in /tmp and in there a link to the keyfile. As the `encrypt` binary runs setuid `krypton3`, you also need to give `krypton3` access to your working directory.
>
>   Here is an example:
>
>   ```bash
>   krypton2@melinda:~$ mktemp -d
>   /tmp/tmp.Wf2OnCpCDQ
>   krypton2@melinda:~$ cd /tmp/tmp.Wf2OnCpCDQ
>   krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ln -s /krypton/krypton2/keyfile.dat
>   krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
>   keyfile.dat
>   krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ chmod 777 .
>   krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ /krypton/krypton2/encrypt /etc/issue
>   krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
>   ciphertext  keyfile.dat
>   ```
>

```bash
sshpass -p ROTTEN ssh krypton2@krypton.labs.overthewire.org -p 2222
```

```bash
krypton2@krypton:~$ cd /krypton/krypton2
krypton2@krypton:/krypton/krypton2$ ls -la
total 32
drwxr-xr-x 2 root     root     4096 Nov  4  2019 .
drwxr-xr-x 8 root     root     4096 Nov  4  2019 ..
-rw-r----- 1 krypton2 krypton2 1815 Nov  4  2019 README
-rwsr-x--- 1 krypton3 krypton2 8970 Nov  4  2019 encrypt
-rw-r----- 1 krypton3 krypton3   27 Nov  4  2019 keyfile.dat
-rw-r----- 1 krypton2 krypton2   13 Nov  4  2019 krypton3
krypton2@krypton:/krypton/krypton2$ ./encrypt

 usage: encrypt foo  - where foo is the file containing the plaintext
krypton2@krypton:/krypton/krypton2$ mkdir /tmp/shiro
krypton2@krypton:/krypton/krypton2$ chmod 777 /tmp/shiro
krypton2@krypton:/krypton/krypton2$ cd /tmp/shiro
krypton2@krypton:/tmp/shiro$ ln -s /krypton/krypton2/keyfile.dat
krypton2@krypton:/tmp/shiro$ ls -la
total 8
drwxrwxrwx 2 krypton2 krypton2 4096 Aug 16 08:18 .
drwxrwx-wt 3 root     root     4096 Aug 16 08:18 ..
lrwxrwxrwx 1 krypton2 krypton2   29 Aug 16 08:18 keyfile.dat -> /krypton/krypton2/keyfile.dat
krypton2@krypton:/tmp/shiro$ echo "ABCDEF" > plaintext
krypton2@krypton:/tmp/shiro$ cat plaintext
ABCDEF
krypton2@krypton:/tmp/shiro$ /krypton/krypton2/encrypt plaintext
krypton2@krypton:/tmp/shiro$ ls
ciphertext  keyfile.dat  plaintext
krypton2@krypton:/tmp/shiro$ cat ciphertext
MNOPQR
krypton2@krypton:/tmp/shiro$ cat /krypton/krypton2/krypton3 | tr 'M-ZA-Lm-za-l' 'A-Za-z'
CAESARISEASY
```

This challenge was similar to the last challenge.

| Cipher        | `MNOPQRSTUVWXYZABCDEFGHIJKLmnopqrstuvwxyzabcdefghijkl`     |
| ------------- | ---------------------------------------------------------- |
| **Plaintext** | **`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`** |

# Level 3

>   Well done. You’ve moved past an easy substitution cipher.
>
>   The main weakness of a simple substitution cipher is repeated use of a simple key. In the previous exercise you were able to introduce arbitrary plaintext to expose the key. In this example, the cipher mechanism is not available to you, the attacker.
>
>   However, you have been lucky. You have intercepted more than one message. The password to the next level is found in the file ‘krypton4’. You have also found 3 other files. (found1, found2, found3)
>
>   You know the following important details:
>
>   -   The message plaintexts are in English (very important) - They were produced from the same key (even better!)
>
>   Enjoy.
>

```bash
sshpass -p CAESARISEASY ssh krypton3@krypton.labs.overthewire.org -p 2222
```

```bash
krypton3@krypton:~$ cd /krypton/krypton3/
krypton3@krypton:/krypton/krypton3$ ls
HINT1  HINT2  README  found1  found2  found3  krypton4
krypton3@krypton:/krypton/krypton3$ cat krypton4
KSVVW BGSJD SVSIS VXBMN YQUUK BNWCU ANMJS
```

Let's take a look at the hints.

```bash
krypton3@krypton:/krypton/krypton3$ cat HINT1
Some letters are more prevalent in English than others.
krypton3@krypton:/krypton/krypton3$ cat HINT2
"Frequency Analysis" is your friend.
```

Hmm, it looks like we need to perform frequency analysis for this challenge.

```bash
krypton/krypton3$ cat found*
CGZNL YJBEN QYDLQ ZQSUQ NZCYD SNQVU BFGBK GQUQZ QSUQN UZCYD SNJDS UDCXJ ZCYDS NZQSU QNUZB WSBNZ QSUQN UDCXJ CUBGS BXJDS UCTYV SUJQG WTBUJ KCWSV LFGBK GSGZN LYJCB GJSZD GCHMS UCJCU QJLYS BXUMA UJCJM JCBGZ CYDSN CGKDC ZDSQZ DVSJJ SNCGJ DSYVQ CGJSO JCUNS YVQZS WALQV SJJSN UBTSX COSWG MTASN BXYBU CJCBG UWBKG JDSQV YDQAS JXBNS OQTYV SKCJD QUDCX JBXQK BMVWA SNSYV QZSWA LWAKB MVWAS ZBTSS QGWUB BGJDS TSJDB WCUGQ TSWQX JSNRM VCMUZ QSUQN KDBMU SWCJJ BZBTT MGCZQ JSKCJ DDCUE SGSNQ VUJDS SGZNL YJCBG UJSYY SNXBN TSWAL QZQSU QNZCY DSNCU BXJSG CGZBN YBNQJ SWQUY QNJBX TBNSZ BTYVS OUZDS TSUUM ZDQUJ DSICE SGNSZ CYDSN QGWUJ CVVDQ UTBWS NGQYY VCZQJ CBGCG JDSNB JULUJ STQUK CJDQV VUCGE VSQVY DQASJ UMAUJ CJMJC BGZCY DSNUJ DSZQS UQNZC YDSNC USQUC VLANB FSGQG WCGYN QZJCZ SBXXS NUSUU SGJCQ VVLGB ZBTTM GCZQJ CBGUS ZMNCJ LUDQF SUYSQ NSYNB WMZSW TBUJB XDCUF GBKGK BNFAS JKSSG QGWDC USQNV LYVQL UKSNS TQCGV LZBTS WCSUQ GWDCU JBNCS UESGN SUDSN QCUSW JBJDS YSQFB XUBYD CUJCZ QJCBG QGWQN JCUJN LALJD SSGWB XJDSU COJSS GJDZS GJMNL GSOJD SKNBJ STQCG VLJNQ ESWCS UMGJC VQABM JCGZV MWCGE DQTVS JFCGE VSQNQ GWTQZ ASJDZ BGUCW SNSWU BTSBX JDSXC GSUJS OQTYV SUCGJ DSSGE VCUDV QGEMQ ESCGD CUVQU JYDQU SDSKN BJSJN QECZB TSWCS UQVUB FGBKG QUNBT QGZSU QGWZB VVQAB NQJSW KCJDB JDSNY VQLKN CEDJU TQGLB XDCUY VQLUK SNSYM AVCUD SWCGS WCJCB GUBXI QNLCG EHMQV CJLQG WQZZM NQZLW MNCGE DCUVC XSJCT SQGWC GJKBB XDCUX BNTSN JDSQJ NCZQV ZBVVS QEMSU YMAVC UDSWJ DSXCN UJXBV CBQZB VVSZJ SWSWC JCBGB XDCUW NQTQJ CZKBN FUJDQ JCGZV MWSWQ VVAMJ JKBBX JDSYV QLUGB KNSZB EGCUS WQUUD QFSUY SQNSU QVJDB MEDGB QJJSG WQGZS NSZBN WUXBN JDSYS NCBWU MNICI STBUJ ACBEN QYDSN UQENS SJDQJ UDQFS UYSQN SKQUS WMZQJ SWQJJ DSFCG EUGSK UZDBB VCGUJ NQJXB NWQXN SSUZD BBVZD QNJSN SWCGQ ABMJQ HMQNJ SNBXQ TCVSX NBTDC UDBTS ENQTT QNUZD BBVUI QNCSW CGHMQ VCJLW MNCGE JDSSV CPQAS JDQGS NQAMJ JDSZM NNCZM VMTKQ UWCZJ QJSWA LVQKJ DNBME DBMJS GEVQG WQGWJ DSUZD BBVKB MVWDQ ISYNB ICWSW QGCGJ SGUCI SSWMZ QJCBG CGVQJ CGENQ TTQNQ GWJDS ZVQUU CZUQJ JDSQE SBXUD QFSUY SQNST QNNCS WJDSL SQNBV WQGGS DQJDQ KQLJD SZBGU CUJBN LZBMN JBXJD SWCBZ SUSBX KBNZS UJSNC UUMSW QTQNN CQESV CZSGZ SBGGB ISTAS NJKBB XDQJD QKQLU GSCED ABMNU YBUJS WABGW UJDSG SOJWQ LQUUM NSJLJ DQJJD SNSKS NSGBC TYSWC TSGJU JBJDS TQNNC QESJD SZBMY VSTQL DQISQ NNQGE SWJDS ZSNST BGLCG UBTSD QUJSU CGZSJ DSKBN ZSUJS NZDQG ZSVVB NQVVB KSWJD STQNN CQESA QGGUJ BASNS QWBGZ SCGUJ SQWBX JDSMU MQVJD NSSJC TSUQG GSUYN SEGQG ZLZBM VWDQI SASSG JDSNS QUBGX BNJDC UUCOT BGJDU QXJSN JDSTQ NNCQE SUDSE QISAC NJDJB QWQME DJSNU MUQGG QKDBK QUAQY JCUSW BGTQL JKCGU UBGDQ TGSJQ GWWQM EDJSN RMWCJ DXBVV BKSWQ VTBUJ JKBLS QNUVQ JSNQG WKSNS AQYJC USWBG XSANM QNLDQ TGSJW CSWBX MGFGB KGZQM USUQJ JDSQE SBXQG WKQUA MNCSW BGQME MUJQX JSNJD SACNJ DBXJD SJKCG UJDSN SQNSX SKDCU JBNCZ QVJNQ ZSUBX UDQFS UYSQN SMGJC VDSCU TSGJC BGSWQ UYQNJ BXJDS VBGWB GJDSQ JNSUZ SGSCG ASZQM USBXJ DCUEQ YUZDB VQNUN SXSNJ BJDSL SQNUA SJKSS GQGWQ UUDQF SUYSQ NSUVB UJLSQ NUACB ENQYD SNUQJ JSTYJ CGEJB QZZBM GJXBN JDCUY SNCBW DQISN SYBNJ SWTQG LQYBZ NLYDQ VUJBN CSUGC ZDBVQ UNBKS UDQFS UYSQN SUXCN UJACB ENQYD SNNSZ BMGJS WQUJN QJXBN WVSES GWJDQ JUDQF SUYSQ NSXVS WJDSJ BKGXB NVBGW BGJBS UZQYS YNBUS ZMJCB GXBNW SSNYB QZDCG EQGBJ DSNSC EDJSS GJDZS GJMNL UJBNL DQUUD QFSUY SQNSU JQNJC GEDCU JDSQJ NCZQV ZQNSS NTCGW CGEJD SDBNU SUBXJ DSQJN SYQJN BGUCG VBGWB GRBDG QMANS LNSYB NJSWJ DQJUD QFSUY SQNSD QWASS GQZBM GJNLU ZDBBV TQUJS NUBTS JKSGJ CSJDZ SGJMN LUZDB VQNUD QISUM EESUJ SWJDQ JUDQF SUYSQ NSTQL DQISA SSGST YVBLS WQUQU ZDBBV TQUJS NALQV SOQGW SNDBE DJBGB XVQGZ QUDCN SQZQJ DBVCZ VQGWB KGSNK DBGQT SWQZS NJQCG KCVVC QTUDQ FSUDQ XJSCG DCUKC VVGBS ICWSG ZSUMA UJQGJ CQJSU UMZDU JBNCS UBJDS NJDQG DSQNU QLZBV VSZJS WQXJS NDCUW SQJDDSNSM YBGVS ENQGW QNBUS KCJDQ ENQIS QGWUJ QJSVL QCNQG WANBM EDJTS JDSAS SJVSX NBTQE VQUUZ QUSCG KDCZD CJKQU SGZVB USWCJ KQUQA SQMJC XMVUZ QNQAQ SMUQG WQJJD QJJCT SMGFG BKGJB GQJMN QVCUJ UBXZB MNUSQ ENSQJ YNCPS CGQUZ CSGJC XCZYB CGJBX ICSKJ DSNSK SNSJK BNBMG WAVQZ FUYBJ UGSQN BGSSO JNSTC JLBXJ DSAQZ FQGWQ VBGEB GSGSQ NJDSB JDSNJ DSUZQ VSUKS NSSOZ SSWCG EVLDQ NWQGW EVBUU LKCJD QVVJD SQYYS QNQGZ SBXAM NGCUD SWEBV WJDSK SCEDJ BXJDS CGUSZ JKQUI SNLNS TQNFQ AVSQG WJQFC GEQVV JDCGE UCGJB ZBGUC WSNQJ CBGCZ BMVWD QNWVL AVQTS RMYCJ SNXBN DCUBY CGCBG NSUYS ZJCGE CJ
```

I copied the chunk of text over to [Cypto Corner](https://crypto.interactive-maths.com/frequency-analysis-breaking-the-code.html) to analyse it's frequencies. Thereafter, I played around with the options and found something interesting when I tried the Count Trigraph option. It showed that `JDS` had the highest frequency. In the English dictionary, `THE` had the the highest frequency.

![frequency_analysis](https://raw.githubusercontent.com/blankshiro/ShiroWriteups/main/OverTheWire/image/Krypton/frequency_analysis.png)

Afterwhich, I tried matching the frequencies but still couldn't find a solution. Therefore, I decided to use an automated solver instead.

I copied the file contents from found and krypton 4 using this command `cat found* krypton4` and paste it into [quipquip](https://quipqiup.com/).

```bash
in cryptography a caesar cipher also known as a caesars cipher the shift cipher caesars code or caesar shift is one of the simplest and most widely known encryption techniques it is a type of substitution cipher in which each letter in the plain text is replaced by a letter some fixed number of positions down the alphabet for example with a shift of a would be replaced by db would become e and soon the method is named after julius caesar who used it to communicate with his generals the encryption step performed by a caesar cipher is often incorporated as part of more complex schemes such as the vigenre cipher and still has modern application in the rot system as with all single alphabet substitution ciphers the caesar cipher is easily broken and in practice offers essentially no communication security shakespeare produced most of his known work between and his early plays were mainly comedies and histories genre she raised to the peak of sophistication and artistry by the end of the sixteenth century next he wrote mainly tragedies until about including hamlet king lear and macbeth considered some of the finest examples in the english language in his last phase he wrote tragicomedies also known as romances and collaborated with other playwrights many of his plays were published in editions of varying quality and accuracy during his lifetime and in two of his former theatrical colleagues published the first folio a collected edition of his dramatic works that included all but two of the plays now recognised as shakespeares although no attendance records for the period survive most biographers agree that shakespeare was educated at the kings new school in stratford a free school chartered in about a quarter of a mile from his home grammar schools varied in quality during the elizabethan era but the curriculum was dictated by law throughout england and the school would have provided an intensive education in latin grammar and the classics at the age of shakespeare married the year old anne hathaway the consistory court of the diocese of worcester issued a marriage licence on november two of hathaways neighbours posted bonds the next day as surety that there were no impediments to the marriage the couple may have arranged the ceremony in some haste since the worcester chancellor allowed the marriage banns to be read once instead of the usual three times annes pregnancy could have been the reason for this six months after the marriage she gave birth to a daughter susanna who was baptised on may twins son hamnet and daughter judith followed almost two years later and were baptised on february ham net died of unknown causes at the age of and was buried on august after the birth of the twins there are few historical traces of shakespeare until he is mentioned as part of the london theatre scene in because of this gap scholars refer to the years between and as shakespeares lost years biographers attempting to account for this period have reported many apocryphal stories nicholas rowe shakespeares first biographer recounted a stratford legend that shakespeare fled the town for london to escape prosecution for deer poaching another eighteenth century story has shakespeare starting his theatrical career minding the horses of theatre patrons in london john aubrey reported that shakespeare had been a country school master some twentieth century scholars have suggested that shakespeare may have been employed as a schoolmaster by alexander hoghton of lancashire a catholic landowner who named a certain william shakesh aftein his will no evidence substantiates such stories other than hearsay collected after his death hereupon le grand arose with a grave and stately air and brought me the beetle from a glass case in which it was enclosed it was a beautiful scarabaeus and at that time unknown to naturalists of course a great prize in a scientific point of view there were two round black spots near one extremity of the back and a long one near the other the scales were exceedingly hard and glossy with all the appearance of burnished gold the weight of the insect was very remarkable and taking all things into consideration i could hardly blame jupiter for his opinion respecting it well done the level four password is brute
```

Now, we can find the password from the decoded text which is `BRUTE`.

# Level 4

>   Good job!
>
>   You more than likely used some form of FA and some common sense to solve that one.
>
>   So far we have worked with simple substitution ciphers. They have also been ‘monoalphabetic’, meaning using a fixed key, and giving a one to one mapping of plaintext (P) to ciphertext (C). Another type of substitution cipher is referred to as ‘polyalphabetic’, where one character of P may map to many, or all, possible ciphertext characters.
>
>   An example of a polyalphabetic cipher is called a Vigenère Cipher. It works like this:
>
>   If we use the key(K) ‘GOLD’, and P = PROCEED MEETING AS AGREED, then “add” P to K, we get C. When adding, if we exceed 25, then we roll to 0 (modulo 26).
>
>   ```
>   P P R O C E E D M E E T I N G A S A G R E E D\
>   K G O L D G O L D G O L D G O L D G O L D G O\
>   ```
>
>   becomes:
>
>   ```
>   P 15 17 14 2 4 4 3 12 4 4 19 8 13 6 0 18 0 6 17 4 4 3\
>   K 6 14 11 3 6 14 11 3 6 14 11 3 6 14 11 3 6 14 11 3 6 14\
>   C 21 5 25 5 10 18 14 15 10 18 4 11 19 20 11 21 6 20 2 8 10 17\
>   ```
>
>   So, we get a ciphertext of:
>
>   ```
>   VFZFK SOPKS ELTUL VGUCH KR
>   ```
>
>   This level is a Vigenère Cipher. You have intercepted two longer, english language messages. You also have a key piece of information. You know the key length!
>
>   For this exercise, the key length is 6. The password to level five is in the usual place, encrypted with the 6 letter key.
>
>   Have fun!
>

```bash
sshpass -p BRUTE ssh krypton4@krypton.labs.overthewire.org -p 2222
```

```bash
krypton4@krypton:~$ cd /krypton/krypton4
krypton4@krypton:/krypton/krypton4$ ls
HINT  README  found1  found2  krypton5
krypton4@krypton:/krypton/krypton4$ cat krypton5
HCIKV RJOX
krypton4@krypton:/krypton/krypton4$ cat HINT
Frequency analysis will still work, but you need to analyse it
by "keylength".  Analysis of cipher text at position 1, 6, 12, etc
should reveal the 1st letter of the key, in this case.  Treat this as
6 different mono-alphabetic ciphers...

Persistence and some good guesses are the key!
```

Let's take a look at one of the text.

```bash
krypton4@krypton:/krypton/krypton4$ cat found1
YYICS JIZIB AGYYX RIEWV IXAFN JOOVQ QVHDL CRKLB SSLYX RIQYI IOXQT WXRIC RVVKP BHZXI YLYZP DLCDI IKGFJ UXRIP TFQGL CWVXR IEZRV NMYSF JDLCL RXOWJ NMINX FNJSP JGHVV ERJTT OOHRM VMBWN JTXKG JJJXY TSYKL OQZFT OSRFN JKBIY YSSHE LIKLO RFJGS VMRJC CYTCS VHDLC LRXOJ MWFYB JPNVR NWUMZ GRVMF UPOEB XKSDL CBZGU IBBZX MLMKK LOACX KECOC IUSBS RMPXR IPJZW XSPTR HKRQB VVOHR MVKEE PIZEX SDYYI QERJJ RYSLJ VZOVU NJLOW RTXSD LYYNE ILMBK LORYW VAOXM KZRNL CWZRA YGWVH DLCLZ VVXFF KASPJ GVIKW WWVTV MCIKL OQYSW SBAFJ EWRII SFACC MZRVO MLYYI MSSSK VISDY YIGML PZICW FJNMV PDNEH ISSFE HWEIJ PSEEJ QYIBW JFMIC TCWYE ZWLTK WKMBY YICGY WVGBS UKFVG IKJRR DSBJJ XBSWM VVYLR MRXSW BNWJO VCSKW KMBYY IQYYW UMKRM KKLOK YYVWX SMSVL KWCAV VNIQY ISIIB MVVLI DTIIC SGSRX EVYQC CDLMZ XLDWF JNSEP BRROO WJFMI CSDDF YKWQM VLKWM KKLOV CXKFE XRFBI MEPJW SBWFJ ZWGMA PVHKR BKZIB GCFEH WEWSF XKPJT NCYYR TUICX PTPLO VIJVT DSRMV AOWRB YIBIR MVWER QJKWK RBDFY MELSF XPEGQ KSPML IYIBX FJPXR ELPVH RMKFE HLEBJ YMWKM TUFII YSUXE VLJUX YAYWU XRIUJ JXGEJ PZRQS TJIJS IJIJS PWMKK KBEQX USDXC IYIBI YSUXR IPJNM DLBFZ WSIQF EHLYR YVVMY NXUSB SRMPW DMJQN SBIRM VTBIR YPWSP IIIIC WQMVL KHNZK SXMLY YIZEJ FTILY RSFAD SFJIW EVNWZ WOWFJ WSERB NKAKW LTCSX KCWXV OILGL XZYPJ NLSXC YYIBM ZGFRK VMZEH DSRTJ ROGIM RHKPQ TCSCX GYJKB ICSTS VSPFE HGEQF JARMR JRWNS PTKLI WBWVW CXFJV QOVYQ UGSXW BRWCS MSCIP XDFIF OLGSU ECXFJ PENZY STINX FJXVY YLISI MEKJI SEKFJ IEXHF NCPSI PKFVD LCWVA OVCSF JKVKX ESBLM ZJICM LYYMC GMZEX BCMKK LOACX KEXHR MVKBS SSUAK WSSKM VPCIZ RDLCF WXOVL TFRDL CXLRC LMSVL YXGSK LOMPK RGOWD TIXRI PJNIB ILTKV OIQYF SPJCW KLOQQ MRHOW MYYED FCKFV ORGLY XNSPT KLIEL IKSDS YSUXR IJNFR GIPJK MBIBF EHVEW IFAXY NTEXR IEWRW CELIW IVPYX CIOTU NKLDL CBFSN QYSRR NXFJJ GKVCH ISGOC JGMXK UFKGR
```

Now, let's copy the text to this [online tool](https://www.dcode.fr/vigenere-cipher) to analyse and crack the text. The cracked key found is `frekey`.

Therefore, we can use this key to decrypt the ciphertext `krypton5` which `clear text`.

# Level 5

>   FA can break a known key length as well. Lets try one last polyalphabetic cipher, but this time the key length is unknown.
>
>   Enjoy.
>

```bash
sshpass -p CLEARTEXT ssh krypton5@krypton.labs.overthewire.org -p 2222
```

```bash
krypton5@krypton:~$ cd /krypton/krypton5
krypton5@krypton:/krypton/krypton5$ ls
README  found1  found2  found3  krypton6
krypton5@krypton:/krypton/krypton5$ cat README
Frequency analysis can break a known key length as well.  Lets try one
last polyalphabetic cipher, but this time the key length is unknown.

Enjoy.
krypton5@krypton:/krypton/krypton5$ cat krypton6
BELOS Z
```

For this challenge, we will use the same [online tool](https://www.dcode.fr/vigenere-cipher) as we did in the previous challenge.

Let's copy the text from `found1 found2 and found3` to the tool and select `AUTOMATIC DECRYPTION`. We will find that the key decrypted is `KEYLENGTH`. Now, let's decrypt the ciphertext which returns `RANDOM`.
