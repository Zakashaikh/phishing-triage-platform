# Case studies — modern samples

30 sample(s) analysed with the offline heuristic detector (no VirusTotal). Unlike the historical evaluation corpus (see RESULTS.md), these are modern messages that carry `Authentication-Results` headers.

**Authentication rules (SPF/DKIM/DMARC) fired on 12/30 scored samples** — on the 2003-era corpus they fired on almost none, which is why they are validated here separately.

**Rules flagged 11/30** at the tuned high-precision operating point; **ML flagged 30/30** at p ≥ 0.5.

| File | Verdict | Score | SPF | DKIM | DMARC | ML p(phish) | Rules fired |
|------|---------|-------|-----|------|-------|-------------|-------------|
| live_00000.eml | SUSPICIOUS | 40 | fail | pass | none | 1.000 | 2 |
| live_00001.eml | MALICIOUS | 55 | fail | fail | none | 1.000 | 3 |
| live_00002.eml | CLEAN | 15 | fail | pass | none | 1.000 | 2 |
| live_00003.eml | SUSPICIOUS | 40 | none | fail | none | 1.000 | 2 |
| live_00004.eml | CLEAN | 0 | pass | pass | pass | 1.000 | 0 |
| live_00005.eml | SUSPICIOUS | 40 | fail | pass | none | 1.000 | 2 |
| live_00006.eml | MALICIOUS | 55 | fail | fail | none | 1.000 | 3 |
| live_00007.eml | SUSPICIOUS | 40 | fail | pass | none | 1.000 | 2 |
| live_00008.eml | SUSPICIOUS | 40 | fail | pass | none | 1.000 | 2 |
| live_00009.eml | CLEAN | 12 | pass | none | pass | 0.997 | 2 |
| live_00010.eml | MALICIOUS | 62 | fail | fail | none | 1.000 | 4 |
| live_00011.eml | CLEAN | 12 | none | none | none | 1.000 | 2 |
| live_00012.eml | CLEAN | 5 | none | none | none | 1.000 | 1 |
| live_00013.eml | CLEAN | 12 | none | none | none | 1.000 | 2 |
| live_00014.eml | CLEAN | 12 | none | none | none | 1.000 | 2 |
| live_00015.eml | CLEAN | 5 | none | none | none | 1.000 | 1 |
| live_00016.eml | CLEAN | 12 | none | none | none | 1.000 | 2 |
| live_00017.eml | CLEAN | 5 | none | none | none | 1.000 | 1 |
| live_00018.eml | SUSPICIOUS | 40 | fail | pass | none | 1.000 | 2 |
| live_00019.eml | CLEAN | 5 | none | none | none | 1.000 | 1 |
| live_00020.eml | CLEAN | 5 | none | pass | pass | 0.995 | 1 |
| live_00021.eml | CLEAN | 12 | none | none | none | 1.000 | 2 |
| live_00022.eml | CLEAN | 12 | none | none | none | 1.000 | 2 |
| live_00023.eml | CLEAN | 0 | none | none | none | 1.000 | 0 |
| live_00024.eml | CLEAN | 0 | none | none | none | 0.999 | 0 |
| live_00025.eml | CLEAN | 5 | pass | pass | pass | 0.695 | 1 |
| live_00026.eml | CLEAN | 0 | none | none | none | 1.000 | 0 |
| live_00027.eml | SUSPICIOUS | 40 | fail | pass | none | 1.000 | 2 |
| live_00028.eml | CLEAN | 5 | none | none | none | 1.000 | 1 |
| live_00029.eml | SUSPICIOUS | 40 | none | fail | none | 1.000 | 2 |

## live_00000.eml — SUSPICIOUS (40)

- **From:** Golden Casino Top <kelly.thompson@utiliseztyuw88.onmicrosoft.com>
- **Subject:** 150 CHANCES TO WIN -----1 MILLION!
- **URLs (defanged):** `hxxps://woondsplay[.]com/4pAZFo22202IGia706rwwghshuju109WDPGKPXGPALHIFY37692URZS1074952z5`, `hxxps://woondsplay[.]com/4kwOGv22202GPyA706rbyvhzpdyo109QQHGOXFHIMTJAHE37692OXNB1074952y5`, `hxxps://woondsplay[.]com/4OISlR22202FnmH706hztbcujwxy109DRSEICYKLLLPQKX37692YKHF1074952U5`, `hxxps://woondsplay[.]com/4UphFj22202iOMF706hocbeamgmv109BTUNRLXFWXQQZUD37692XTMU1074952a5`, `hxxps://woondsplay[.]com/4cEavg22202DYOk706qwaumszaig109NERVLGRISSGTXED37692EFMQ1074952J5`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `lookalike_domain` | 25 | Domain utiliseztyuw88.onmicrosoft.com looks like microsoft.com | T1583.001 |

## live_00001.eml — MALICIOUS (55)

- **From:** Plinko Gold Rewards <frances.perez@personnaliser9658.onmicrosoft.com>
- **Subject:** Claim free — no deposit, no catch ✅
- **URLs (defanged):** `hxxp://cricktoon[.]org/4iFspS18914VEhh1483pezakhfsqa124HVLZALTQDRQXXKY105755XAZE591444L1`, `hxxp://cricktoon[.]org/4ROLqO18914LzAG1483fyquncdwdx124BTUFTPHBBIAYSEF105755UVDA591444b1`, `hxxp://cricktoon[.]org/5aZJgs18914xcwP1483bctfmioxba124FKDUULELENSWWLA105755WXOS591444a1`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `dkim_fail` | 15 | DKIM signature failed | T1672 |
| `lookalike_domain` | 25 | Domain personnaliser9658.onmicrosoft.com looks like microsoft.com | T1583.001 |

## live_00002.eml — CLEAN (15)

- **From:** Casino rewards [redacted] <bailey.wilson@totaliuyt03.onmicrosoft.com>
- **Subject:** Unbelievable 200 FREE SPINS Welcome Bonus!
- **URLs (defanged):** `hxxps://woondsplay[.]com/4pwvoj22183hEOp682uibsyialqe109FWPZCUDOJKFKHEL37692JSFO1056475J5`, `hxxps://woondsplay[.]com/4RAgky22183oPEn682uqyiuwazai109OKCNDWOHTBVIWAV37692CEBK1056475E5`, `hxxps://woondsplay[.]com/4cRrnv22183cWVA682qnnhzfqnzq109STXVALUBKKXUSXY37692NAON1056475w5`, `hxxps://woondsplay[.]com/4rcEWe22183xhDY682ogvxofcxys109WJXUKZSGKTMPTVN37692TXZJ1056475p5`, `hxxps://woondsplay[.]com/4MzOJT22183isUS682gkahjeaerc109MGAPDPBOOGCNFMV37692OQHH1056475c5`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `return_path_mismatch` | 0 | From domain pot but Return-Path domain totaliuyt03.onmicrosoft.com | T1566.002 |

## live_00003.eml — SUSPICIOUS (40)

- **From:** CAA Member Safety Team <jamie.young@collins351.onmicrosoft.com>
- **Subject:** What would you do if your kids were trapped in the car?
- **URLs (defanged):** `hxxps://cricktoon[.]org/rd/4oSEPZ18904DXLn1445ufedwbwgqz124UZAWURVCOTQOELW105755JGOX589349P1`, `hxxps://cricktoon[.]org/rd/4XBMdD18904ViFn1445dxinlisxzn124TCBHKQERCCBDXNY105755AWGI589349K1`, `hxxp://cricktoon[.]org/rd/5yrQpA18904ysmI1445qomqzraiud124QGGIODGNCROVPJD105755ONGG589349R1`, `hxxps://cricktoon[.]org/rd/4sXyTc18904rnsQ1445vlnucflyqq124UQHOXBYTORFYZCG105755TUHL589349m1`, `hxxps://cricktoon[.]org/rd/4JWerg18904faie1445cqhzdugplb124MHIEZILDSMVGUDE105755WYKO589349r1`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `dkim_fail` | 15 | DKIM signature failed | T1672 |
| `lookalike_domain` | 25 | Domain collins351.onmicrosoft.com looks like microsoft.com | T1583.001 |

## live_00004.eml — CLEAN (0)

- **From:** Sophie <info@mail.empowertags.com>
- **Subject:** Ik ben benieuwd naar jou...
- **URLs (defanged):** `hxxps://mail[.]whenthefork[.]com/index.php/campaigns/yr960lha38146/track-url/mo677sdndb34c/64c57498f4f0cb342417b112c6996e3c5176c14d`, `hxxps://mail[.]whenthefork[.]com/index.php/campaigns/yr960lha38146/track-url/mo677sdndb34c/856d59fad108b5ee7df03943df12aa6d749903ab`

## live_00005.eml — SUSPICIOUS (40)

- **From:** 🤑Dragonia bonus🤑 <reese.sanchez@totaliuyt03.onmicrosoft.com>
- **Subject:** 200 FREE SPINS Welcome Bonus PENDING IN YOUR ACCOUNT
- **URLs (defanged):** `hxxps://woondsplay[.]com/rd/index.php?search=4&d22158&hxlrm=705-109&lm=37692UQWJ1056649&sd=5&page=8FcFVAziOdX029K`, `hxxps://woondsplay[.]com/rd/index.php?search=4&d22158&fgrdm=705-109&lm=37692ZNXI1056649&sd=5&page=I17KRsyrl3NHA4B`, `hxxps://woondsplay[.]com/rd/index.php?search=4&d22158&urgyk=705-109&lm=37692CRQS1056649&sd=5&page=9PFeBssFZPqYB3H`, `hxxp://woondsplay[.]com/rd/index.php?search=5&d22158&wfftp=705-109&lm=37692MVIX1056649&sd=5&page=lwAMwLRDiiXLAGw`, `hxxps://woondsplay[.]com/rd/index.php?search=4&amp;d22158&amp;hxlrm=705-109&amp;lm=37692UQWJ1056649&amp;sd=5&amp;page=8FcFVAziOdX029K`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `lookalike_domain` | 25 | Domain totaliuyt03.onmicrosoft.com looks like microsoft.com | T1583.001 |

## live_00006.eml — MALICIOUS (55)

- **From:** Jetterix-Hochdruckdüse <lane.martinez@kayapo.onmicrosoft.com>
- **Subject:** Verwandeln Sie Ihren Gartenschlauch in einen Hochdruckreiniger
- **URLs (defanged):** `hxxp://rangbazi[.]org/4zJkcx18910HPOV1515ewwbbdywtq114GMYOLXNZVRMEFNA23463UWWO587135u1`, `hxxp://rangbazi[.]org/4iXvLw18910qBEY1515jgxgjavaeb114LDLSQOYLOZGOHLJ23463ZXMH587135T1`, `hxxp://rangbazi[.]org/4IWcYQ18910VmCm1515ebtjreymxm114CHEOWPTYLFNTLBX23463EGXW587135x1`, `hxxp://rangbazi[.]org/4xLtir18910IXoS1515qhelanswsi114FEEDXHIRDSOMJMS23463NHJZ587135U1`, `hxxp://rangbazi[.]org/4FRpMZ18910WWpw1515zhhcpduhht114HKUDZKIJFHXKQAR23463FIPP587135s1`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `dkim_fail` | 15 | DKIM signature failed | T1672 |
| `lookalike_domain` | 25 | Domain kayapo.onmicrosoft.com looks like microsoft.com | T1583.001 |

## live_00007.eml — SUSPICIOUS (40)

- **From:** 💲Casea bonus💲 <finley.green@authentication123uyt543.onmicrosoft.com>
- **Subject:** Unlock 250% up to $4,500 + 350 FS and take your experience further!
- **URLs (defanged):** `hxxps://woondsplay[.]com/index.php?search=4&d22136&dtnlh=618-109&lm=37692PCLS1076529&sd=5&page=Xv7cI0aDahad7jQ`, `hxxps://woondsplay[.]com/index.php?search=4&d22136&runsb=618-109&lm=37692CZHT1076529&sd=5&page=kfLZxAU9nw6TN7u`, `hxxps://woondsplay[.]com/index.php?search=4&d22136&twtbt=618-109&lm=37692LJVS1076529&sd=5&page=QZ9KqQYZvjbiPsG`, `hxxps://woondsplay[.]com/index.php?search=4&d22136&uwjlx=618-109&lm=37692KWHO1076529&sd=5&page=uIcqnCHbNic5FoG`, `hxxps://woondsplay[.]com/index.php?search=4&d22136&fypvt=618-109&lm=37692AABB1076529&sd=5&page=GekoumKH7IXsdIy`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `lookalike_domain` | 25 | Domain authentication123uyt543.onmicrosoft.com looks like microsoft.com | T1583.001 |

## live_00008.eml — SUSPICIOUS (40)

- **From:** Casinova Bonus <cameron.robinson@sbdsdbdcelebsnetworthnet.onmicrosoft.com>
- **Subject:** Message Content Casinova $3,000 bonus + 350 FS
- **URLs (defanged):** `hxxps://woondsplay[.]com/4qWnaJ22115Njqj702qzszvhpugh205ZGQCGBXCOCQIGVH164627TNMP1071517g5`, `hxxps://woondsplay[.]com/4irVLo22115yhmZ702bwnlkjbtuk205OUCEQGQBYCPBZNU164627QNLC1071517k5`, `hxxps://woondsplay[.]com/4DuWfj22115kODJ702uxitglauec205RFCRDOPGYZAZHFW164627DCGO1071517d5`, `hxxps://woondsplay[.]com/4uHGoR22115DAsP702ksthtapriv205KQZLDBAAJSVBPHF164627KYSS1071517z5`, `hxxps://woondsplay[.]com/4ItiDq22115ERdy702juvbdwlslh205PITSYOASSUISKMC164627OTWP1071517E5`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `lookalike_domain` | 25 | Domain sbdsdbdcelebsnetworthnet.onmicrosoft.com looks like microsoft.com | T1583.001 |

## live_00009.eml — CLEAN (12)

- **From:** Your Cold Sore <salama.asab@pme.suezuni.edu.eg>
- **Subject:** Herpes Virus Hiding Place Revealed! (Nobody Believed This!)
- **URLs (defanged):** `hxxps://track[.]kolabokoliya[.]vip/track_click.php?e=rodrigo-f-p%40hotmail.com&amp;u=https%3A%2F%2Fstorage.googleapis.com%2Fseawcdef%2FTonic-Greensas.htm`, `hxxps://track[.]kolabokoliya[.]vip/track_click.php?e=rodrigo-f-p%40hotmail.com&amp;u=https%3A%2F%2Fstorage.googleapis.com%2Fseawcdef%2Funsb_Tonic-Greensas.htm`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain pme.suezuni.edu.eg but Reply-To domain 2ndal7.com | T1566.002 |
| `urgency_language` | 7 | Urgency/credential language: click here | T1656 |

## live_00010.eml — MALICIOUS (62)

- **From:** Reelraven Alerts <austin.torres@rtyeldersclash.onmicrosoft.com>
- **Subject:** 🚨 Claim your bonus now before access expires
- **URLs (defanged):** `hxxps://cricktoon[.]org/rd/4eVNIX18924nVGP1517jhbqrnpbmx124OLTMMGTPGEECOSY105755CZPV594088o1`, `hxxps://cricktoon[.]org/rd/4baSUe18924DBov1517eabdfqzcjr124QQKAJEMIUDHOOGT105755TETP594088b1`, `hxxps://cricktoon[.]org/rd/4kfPxb18924kbwE1517enlfvoaxje124FEFQYOIGBODYHIJ105755NNCS594088y1`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `dkim_fail` | 15 | DKIM signature failed | T1672 |
| `lookalike_domain` | 25 | Domain rtyeldersclash.onmicrosoft.com looks like microsoft.com | T1583.001 |
| `urgency_language` | 7 | Urgency/credential language: expire | T1656 |

## live_00011.eml — CLEAN (12)

- **From:** Token Revolut ������ <no-reply@dhxqgeeynxboqp.com>
- **Subject:** V��RIFIER MON ALLOCATION MAINTENANT ���
- **URLs (defanged):** `hxxp://bensalemdentist[.]com/?act=cl&amp;pid=1324_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5025&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxp://bensalemdentist[.]com/?act=un&amp;pid=1324_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5025&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain dhxqgeeynxboqp.com but Reply-To domain in2.getdrip.com | T1566.002 |
| `urgency_language` | 7 | Urgency/credential language: expire | T1656 |

## live_00012.eml — CLEAN (5)

- **From:** RACSTAR ������ <no-reply@lbjkwcesrlulwz>
- **Subject:** IMPORTANT Statut de votre dossier : Pr��t pour versement ���
- **URLs (defanged):** `hxxps://kyempapu[.]org/?act=cl&amp;pid=1321_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5449&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxps://kyempapu[.]org/?act=un&amp;pid=1321_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5449&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain lbjkwcesrlulwz but Reply-To domain in2.getdrip.com | T1566.002 |

## live_00013.eml — CLEAN (12)

- **From:** Token Revolut ������ <no-reply@knaemvjdyftoya.com>
- **Subject:** V��RIFIER MON ALLOCATION MAINTENANT ���
- **URLs (defanged):** `hxxp://kyempapu[.]org/?act=cl&amp;pid=1335_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5025&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxp://kyempapu[.]org/?act=un&amp;pid=1335_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5025&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain knaemvjdyftoya.com but Reply-To domain in2.getdrip.com | T1566.002 |
| `urgency_language` | 7 | Urgency/credential language: expire | T1656 |

## live_00014.eml — CLEAN (12)

- **From:** Chronopost  ���� <no-reply@odzahquwvpiypw>
- **Subject:** Votre colis est bloqu�� au centre
- **URLs (defanged):** `hxxp://kyempapu[.]org/?act=cl&amp;pid=1338_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5114&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxp://kyempapu[.]org/?act=un&amp;pid=1338_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5114&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain odzahquwvpiypw but Reply-To domain in2.getdrip.com | T1566.002 |
| `urgency_language` | 7 | Urgency/credential language: expire | T1656 |

## live_00015.eml — CLEAN (5)

- **From:** Sophie Martin ���� <no-reply@nhqvmisiuhyhcbscbghpjapoc>
- **Subject:** Votre offre de rachat de cr��dits �� taux comp��titif ���
- **URLs (defanged):** `hxxps://kyempapu[.]org/?act=cl&amp;pid=1332_rd&amp;uid=20&amp;cmpid=0&amp;ofid=4600&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxps://kyempapu[.]org/?act=un&amp;pid=1332_rd&amp;uid=20&amp;cmpid=0&amp;ofid=4600&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain nhqvmisiuhyhcbscbghpjapoc but Reply-To domain in2.getdrip.com | T1566.002 |

## live_00016.eml — CLEAN (12)

- **From:** Chronopost  ���� <no-reply@jumrvnwrkleuhq>
- **Subject:** Livraison en attente  ���
- **URLs (defanged):** `hxxps://kyempapu[.]org/?act=cl&amp;pid=1327_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5114&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxps://kyempapu[.]org/?act=un&amp;pid=1327_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5114&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain jumrvnwrkleuhq but Reply-To domain in2.getdrip.com | T1566.002 |
| `urgency_language` | 7 | Urgency/credential language: expire | T1656 |

## live_00017.eml — CLEAN (5)

- **From:** Sophie Martin ���� <no-reply@djrvivjlxniggqgrobrxlxtzv>
- **Subject:** Votre offre de rachat de cr��dits �� taux comp��titif ���
- **URLs (defanged):** `hxxp://kyempapu[.]org/?act=cl&amp;pid=1336_rd&amp;uid=20&amp;cmpid=0&amp;ofid=4600&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxp://kyempapu[.]org/?act=un&amp;pid=1336_rd&amp;uid=20&amp;cmpid=0&amp;ofid=4600&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain djrvivjlxniggqgrobrxlxtzv but Reply-To domain in2.getdrip.com | T1566.002 |

## live_00018.eml — SUSPICIOUS (40)

- **From:** free spin <charlie.torres@totaliuyt04.onmicrosoft.com>
- **Subject:** Final update - Promo code winner Z60Tk668!
- **URLs (defanged):** `hxxps://woondsplay[.]com/index.php?search=4&d22480&elmsb=703-109&lm=37692IQBA1056900&sd=5&page=Zco8ihUQ3jOCC2t`, `hxxps://woondsplay[.]com/index.php?search=4&d22480&xevuq=703-109&lm=37692XUAD1056900&sd=5&page=S8iTRnNQdJvq5xf`, `hxxp://woondsplay[.]com/rd/index.php?search=5&d22480&ijbma=703-109&lm=37692FREL1056900&sd=5&page=5K5vlhSZ86www5n`, `hxxps://woondsplay[.]com/index.php?search=4&amp;d22480&amp;elmsb=703-109&amp;lm=37692IQBA1056900&amp;sd=5&amp;page=Zco8ihUQ3jOCC2t`, `hxxps://woondsplay[.]com/index.php?search=4&amp;d22480&amp;xevuq=703-109&amp;lm=37692XUAD1056900&amp;sd=5&amp;page=S8iTRnNQdJvq5xf`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `lookalike_domain` | 25 | Domain totaliuyt04.onmicrosoft.com looks like microsoft.com | T1583.001 |

## live_00019.eml — CLEAN (5)

- **From:** RACSTAR ������ <no-reply@tfttrxwmgewoil>
- **Subject:** IMPORTANT Statut de votre dossier : Pr��t pour versement ���
- **URLs (defanged):** `hxxps://kyempapu[.]org/?act=cl&amp;pid=1321_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5449&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxps://kyempapu[.]org/?act=un&amp;pid=1321_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5449&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain tfttrxwmgewoil but Reply-To domain in2.getdrip.com | T1566.002 |

## live_00020.eml — CLEAN (5)

- **From:** Your Penis <mfreddy@ugb.edu.sv>
- **Subject:** Cheating Wives Exposed
- **URLs (defanged):** `hxxps://track[.]kolabokoliya[.]vip/track_click.php?e=rodrigo-f-p%40hotmail.com&amp;u=https%3A%2F%2Fstorage.googleapis.com%2Fseawcdef%2FStratos-Alphaa.htm`, `hxxps://track[.]kolabokoliya[.]vip/track_click.php?e=rodrigo-f-p%40hotmail.com&amp;u=https%3A%2F%2Fstorage.googleapis.com%2Fseawcdef%2Funsb_Stratos-Alphaa.htm`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain ugb.edu.sv but Reply-To domain 2ndal7.com | T1566.002 |

## live_00021.eml — CLEAN (12)

- **From:** Chronopost  ���� <no-reply@tiwkxepmlcwjec>
- **Subject:** Livraison en attente  ���
- **URLs (defanged):** `hxxps://kyempapu[.]org/?act=cl&amp;pid=1327_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5114&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxps://kyempapu[.]org/?act=un&amp;pid=1327_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5114&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain tiwkxepmlcwjec but Reply-To domain in2.getdrip.com | T1566.002 |
| `urgency_language` | 7 | Urgency/credential language: expire | T1656 |

## live_00022.eml — CLEAN (12)

- **From:** Token Revolut ������ <no-reply@gejuwpfvhziwvp.com>
- **Subject:** V��RIFIER MON ALLOCATION MAINTENANT ���
- **URLs (defanged):** `hxxps://kyempapu[.]org/?act=cl&amp;pid=1331_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5025&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxps://kyempapu[.]org/?act=un&amp;pid=1331_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5025&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain gejuwpfvhziwvp.com but Reply-To domain in2.getdrip.com | T1566.002 |
| `urgency_language` | 7 | Urgency/credential language: expire | T1656 |

## live_00023.eml — CLEAN (0)

- **From:** Fibrepourtous.fr ��� <SNLCTC48@F15OHZNAWS03XM546WOITWUPXS0D.com>
- **Subject:** Votre adresse est ��ligible : -300���/an sur la fibre ? ����
- **URLs (defanged):** `hxxps://kyempapu[.]org/?act=cl&amp;pid=1330_rd&amp;uid=20&amp;cmpid=0&amp;ofid=4865&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxps://kyempapu[.]org/?act=un&amp;pid=1330_rd&amp;uid=20&amp;cmpid=0&amp;ofid=4865&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

## live_00024.eml — CLEAN (0)

- **From:** Akusoli Comfort ��� <SIDVGL1M@8DDW299YD3LSARPE5KWZZCHBHC2B.com>
- **Subject:** Say Goodbye to Foot Pain with Akusoli ����
- **URLs (defanged):** `hxxp://kyempapu[.]org/ftCLKf`, `hxxp://kyempapu[.]org/hCIGFI`

## live_00025.eml — CLEAN (5)

- **From:** Men���s Wellness Today <iJTFaAccn95CWL5@jwgmedia.com>
- **Subject:** The Safe, Natural Way to Feel More Energetic and Ready
- **URLs (defanged):** `hxxps://storage[.]googleapis[.]com/yxyltdgaoiqiztu/vbubnfvjsg.html#tw1TT0GEpW4zyBKfD8ZLK/6Z/ms3kvQAWGCHsd3OSXBupt8tIz/v_YdvBck/oBZ4fP3XAjS0H5xBKTqXRy/v5/eZJw35H2wuLt7kuZ0TI3a/rveMddY/llLDACzy9VsdFa5jNYFSKrojT/7Mdx7/ZQL7ayefTWrV1oNBTApBG/vY_M/fgVkbi5u6eN8uSvXuKqLkb2Tf/e5e_rx5/liIdTJcQHMexZ6NdVfiiylGT/`, `hxxps://storage[.]googleapis[.]com/yxyltdgaoiqiztu/vbubnfvjsg.html#mVzxUlUyLgn5m18rUkSO8VF/n4/Seaf49Gya1rFBP7f9AkX/v_YdvBck/pAKrmBumtTxbLB4nsrK5MGGRl/v5/eeNeFvckgAJf4LnhuI0Gu/rveMddY/PUuGXl7fDZgY5Vl9UxfT/7Mdx7/gjDboBGoO593omiYcojemL99/vY_M/ftaEwZ3Y7bDMxqoTfUORBpyhM/e5e_rx5/5eRTy039x4Ouv6UmZ9rz3ovB/`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain jwgmedia.com but Reply-To domain brendamurphyrealestate.com | T1566.002 |

## live_00026.eml — CLEAN (0)

- **From:** Assur Vite  ������ <Z2A2WT6C@2WQGU0FR55JCIOHTRJ0IGUPG20ZG.com>
- **Subject:** La meilleure compl��mentaire pour vous d��s 27 euros/mois �������
- **URLs (defanged):** `hxxps://kyempapu[.]org/?act=cl&amp;pid=1457_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5764&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`, `hxxps://kyempapu[.]org/?act=un&amp;pid=1457_rd&amp;uid=20&amp;cmpid=0&amp;ofid=5764&amp;lid=466&amp;cid=6983baaef125cc1528f7e2f6`

## live_00027.eml — SUSPICIOUS (40)

- **From:** Unlock 400 Free Spins <drew.martinez@multifacteur03.onmicrosoft.com>
- **Subject:** Your Winning Journey Starts at Roman Casino
- **URLs (defanged):** `hxxps://woondsplay[.]com/4RUwLy22752jYVg715lneaozoeyj205FUKXBHBOMCLNLNZ164627RNYJ1099697j5`, `hxxps://woondsplay[.]com/4twMli22752yrOA715pogmefhghq205NHZVFKDRJZQXRWA164627YOGH1099697y5`, `hxxps://woondsplay[.]com/4tjmtr22752uYSM715btnrauvzwc205RYVEOEPTMNZSYGW164627GPVU1099697J5`, `hxxps://woondsplay[.]com/4qZkwa22752CuYT715qubidujmst205YFHIGLYOEZMPVQD164627GCMU1099697D5`, `hxxps://woondsplay[.]com/4pTOGn22752gzlK715ondmewpcnp205WTMHXCVOOHYECOC164627SAMB1099697p5`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `spf_fail` | 15 | SPF check failed | T1672 |
| `lookalike_domain` | 25 | Domain multifacteur03.onmicrosoft.com looks like microsoft.com | T1583.001 |

## live_00028.eml — CLEAN (5)

- **From:** Pedagio Digital <consultardebitos@pedagiodigital896710040>
- **Subject:** Pendência identificada em 19/05/2026 — veja agora.
- **URLs (defanged):** `hxxps://microsoft[.]com-403320172pedagio@97[.]244[.]72[.]148[.]host[.]secureserver[.]net/acess/?email=[redacted]`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `reply_to_mismatch` | 5 | From domain pedagiodigital896710040 but Reply-To domain notificacoes | T1566.002 |

## live_00029.eml — SUSPICIOUS (40)

- **From:** Your Free Bonus <ocean.brown@collins351.onmicrosoft.com>
- **Subject:** Play for free tonight — no deposit, no catch
- **URLs (defanged):** `hxxp://cricktoon[.]org/4qDqYf19089ZOIh1483luexbfursh124KASSXTREVGCGFYX105755UTRG589236h1`, `hxxp://cricktoon[.]org/4sCXHW19089RrDU1483duoszpdgla124MAXQTZCRAGQDYMD105755FIOL589236x1`, `hxxp://cricktoon[.]org/4wRyjm19089OLqt1483hrebpeqqqc124JEBRACDHDCUNUSP105755SBAE589236x1`, `hxxp://cricktoon[.]org/5kFiVD19089nCXM1483jpqbhiuoql124TZNORGIPFVEKEYH105755MRFX589236l1`

| Rule | Points | Detail | ATT&CK |
|------|--------|--------|--------|
| `dkim_fail` | 15 | DKIM signature failed | T1672 |
| `lookalike_domain` | 25 | Domain collins351.onmicrosoft.com looks like microsoft.com | T1583.001 |
