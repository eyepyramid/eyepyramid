# What we know (technically) about EyePyramid

**WARNING:** this is the most up to date version among the various posts that I've released. So, please try to refer to this. Despite being the most up to date one, it's not guaranteed to be 100% accurate: I publish modifications and updates as I analyze the technical info at my disposal, trying to do my best to keep up.

This personal note, translation of its Italian version “[Cosa sappiamo su EyePyramid](https://medium.com/@phretor/cosa-sappiamo-su-eyepyramid-61b5b88c63b8#.fsgi8ch9g),” is meant to be a container of distilled technical information currently available on the EyePyramid case. It is mainly based on [the only official source](http://www.agi.it/pictures/pdf/agi/agi/2017/01/10/132733992-5cec4d88-49a1-4a00-8a01-dde65baa5a68.pdf), slightly enriched through some OSINT and personal searches.

Please feel free to comment here, or send me feedback at via email to: federico at maggi dot cc.
 
## What happened?

Sensitive information was exfiltrated from high-value targets on the Italian scene, for instance:

  * 18327 usernames
  * 1793 passwords
  * keystrokes stolen via a keylogger

Roughly, 87GB of data overall, of course there is much more bejond this, but I don't want to repeat what's already clearly written in the PDF linked above.

## When?

Since 2012. Earlier versions of the malware malware (of uknonwn origin, [except some speculations that would link this to Project Sauron, which I don't believe](http://www.mainfatti.it/spionaggio/Cyberspionaggio-malware-EyePyramid-fa-parte-del-Progetto-Sauron_0182650033.htm)) have been probably used in 2008, 2010, 2011, and 2014 in various spear-phishing campaings (against various targets, including Italian targets).

## Who are the victims?

The exfiltrated information is referred to, produced/exchanged by, or otherwise possessed by private and public Italian citizens, operating in key positions of the Italian State. The known domains of the victims are:

  * enav.it (unconfirmed)
  * istruzione.it
  * gdf.it
  * bancaditalia.it
  * camera.it
  * senato.it
  * esteri.it
  * tesoro.it
  * finanze.it
  * interno.it
  * istut.it
  * matteorenzi.it
  * partitodemocratico.it
  * pdl.it
  * cisl.it
  * comune.roma.it
  * regione.campania.it
  * regione.lombardia.it
  * unibocconi.it
  * enel.it
  * aceaspa.it
  * eni.it
  * finmeccanica.com
  * fondiaria-sai.it

## How?

From what we know, the attacker (or the attackers):

  1. cooked (or, better, modified an existing) malware that, among the traditional C2 communication techniques, it leverages MailBee.NET.dll APIs (a .NET library used for building mail software) to send the exfiltrated data out to dropzones. In particular, one of the MailBee license keys used by the malware writer is (? = uknownw) MN600-D8102?501003102110C5114F1?18-0E8CI (other keys are reported below)
	2. comprmised (we don't know how) some email accounts (at least 15, from what we know). In particular, accounts belonging to various attorneys and associates,
	3. the attacker (or the malware, it's not really clear) connects via Tor (for what is worth, the only known exit node is 37.49.226[.]236)
  4. using an email mail server (among the known ones, Aruba's MX 62.149.158[.]90) the attacker sends spear-phisihing email messages to the victims using the compromised accounts s the sender, containing a malicious attachment (unverified information: someone believes the attachment is a PDF)
  5. wait for the victims to open the attachment, which drops the malware executable
	6. the malware sends exfiltrated data to various dropzones (i.e., email addresses in use by the attacker) 

## Details

### Related Samples (not yet 100% EyePyramid!)

* [d3ad32bcb255e56cd2a768b3cbf6bafda88233288fc6650d0dfa3810be75f74c](https://www.virustotal.com/en/file/d3ad32bcb255e56cd2a768b3cbf6bafda88233288fc6650d0dfa3810be75f74c/analysis/)

This has been found via “MSIL/Cribz.a”, a clue by [@ReaQta](https://twitter.com/@ReaQta) together with [@emgent](https://twitter.com/@emgent) who convinced me that it's actually a relevant sample. I'm still skeptical, though. It's definitely relevant and related based on what's in it, but it's **not** 2016's EyePyramid.

An analysis has been started on [Hybrid Analysis](https://www.hybrid-analysis.com/sample/d3ad32bcb255e56cd2a768b3cbf6bafda88233288fc6650d0dfa3810be75f74c) (not by me).

### Encryption (from the related sample)
* 3DES

### Mailservers

I found these mailservers being used by the malware. Not clear (yet) if its only for sending emails, or for information harvesting too.

* smtp[.]gmail[.]com
* imap[.]gmail[.]com
* pop[.]gmail[.]com
* mail[.]libero[.]it
* out[.]alice[.]it
* smtp[.]tiscali[.]it
* box[.]tin[.]it
* mail[.]tin[.]it
* imap[.]impresasemplice[.]it
* out[.]impresasemplice[.]it
* imap[.]fastwebnet[.]it
* smtp[.]fastwebnet[.]it
* in[.]alice[.]it
* out[.]alice[.]it
* in[.]virgilio[.]it
* out[.]virgilio[.]it
* imap[.]gmail[.]com
* imap[.]gmx[.]com
* imap[.]interfree[.]it
* imap[.]mail[.]ru
* imap[.]tiscali[.]it
* mail[.]katamail[.]com
* mail[.]live[.]com
* mail[.]supereva[.]it
* popmail[.]libero[.]it

### Incomplete list of targeted files
* .bmp
* .cab
* .dwg
* .dxf
* .eml
* .eps
* .htm
* .html
* .jpg
* .ppt
* .pptx
* .pps
* .pst
* .rar
* .rdp
* .rtf
* .sln
* .sql
* .tif
* .txt
* .wpd
* .wri
* .xls
* .xlsx
* .xml
* .zip
* .zipx

### Email addresses

* used by the recent variant as dropzones:
	* gpool@hostpenta[.]com
	* hanger@hostpenta[.]com
	* hostpenta@hostpenta[.]com
	* ulpi715@gmx[.]com - not sure about this

* used in 2010 for the same purpose
	* purge626@gmail[.]com
	* tip848@gmail[.]com
	* dude626@gmail[.]com
	* octo424@gmail[.]com

* used as senders in spear-phishing messages
	* antoniaf@poste[.]it
	* mmarcucci@virgilio[.]it
	* i.julia@blu[.]it
	* g.simeoni@inwind[.]it
	* g.latagliata@live[.]com
	* rita.p@blu[.]it
	* b.gaetani@live[.]com
	* gpierpaolo@tin[.]it
	* e.barbara@poste[.]it
	* stoccod@libero[.]it
	* g.capezzone@virgilio[.]it
	* baldarim@blu[.]it
	* ?.elsajuliette@blu[.]it
	* dipriamoj@alice[.]it
	* izabelle.d@blu[.]it

* other (cannot link it to anything)
	* lu_1974@hotmail[.]com

### Hosts/domains (some are C&C)
* eyepyramid[.]com
* hostpenta[.]com
* ayexisfitness[.]com
* enasrl[.]com
* eurecoove[.]com
* marashen[.]com
* millertaylor[.]com
* occhionero[.]com
* occhionero[.]info
* wallserv[.]com
* westlands[.]com

### URLs
* hostpenta[.]com/contacts
* westlands[.]com/Web/Sites/hostpenta[.]com
* URL paths (likely related to traffic directed to the C2)
  * /bin
  * /captcha
  * /config
  * /fail
  * /jobs
  * /obj
  * /replace
  * /cherr
  * /cloud
  * /params
  * /pks
  * /tasks
  * /decepk

### IPs (C&Cs?)
* 217.115.113[.]181 (Ireland)
* 216.176.180[.]188 (Seattle, Washington, US) 
* 65.98.88[.]29 (Clifton, New York, US)
* 199.15.251[.]75 (Baltimore, Maryland, US)
* 216.176.180[.]181 (Seattle, Washington, US)

### Filenames
* qbpye.exe - this is the name of an executable written by the malware (obtained from related sample analysis)
  * there are at least other names used by the malware to plant itself on the FS, but these are not confirmed IOCs, so I'm not going to share them yet
* InfoPyramid.accdb - database found on hostpenda[.]com containing exfiltrated data
* hiwater.mrk
* smtps.xml
* graph.bak
* tasks.xml
* alerts.txt

### Building info (and other source-code-related info)
From the related sample above, I could determie that the code is written in .NET (>= 4.5.x), source-code-level obfuscation, plus some other obfuscation on the executable. Uses reflection, and I can confirm the use of MailBee, although I haven't been able to recover the license key.

* Visual Studio was used to build “Eye Manager,” (allegedly the name of the botmaster component) 
* Hangeron (module name)
* Mailfaker (module name)
* fHangeron.Menu.Web.vb (file name)
* m.Core.vb (file name)
* cEmailJob.vb (file name)
* mWakeUP.vb (file name)
* ds1 (variable name)
* ms1 (variable name)
* dc1 (variable name)
* ds2 (variable name)
* ms2 (variable name)
* dc2 (variable name)

### Other strings
* MDaemon
* MailDemon (odd: any English-speaking dev would have used “MailDaemon”, unless this is a typo introduced in the Police report)
* InfoPyramid
* MN600-849590C695DFD9BF69481597241E-668C (.NET MailBee license key)
* MN600-841597241E8D9BF6949590C695DF-774D (.NET MailBee license key)
* MN600-3E3A3C593AD5BAF50F55A4ED60F0-385D (.NET MailBee license key)
* MN600-AD58AF50F55A60E043E3A3C593ED-874A (.NET MailBee license key)
* PCMDPWD (tiro a indovinare: PC Mail Daemon Password?)
* WEBDECCERTPWDNFW

