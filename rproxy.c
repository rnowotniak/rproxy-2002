/*
 *     rproxy.c
 *     ~~~~~~~~
 *     rnowotniak@gmail.com
 *     Sob 10 Sie 20:25:57 2002
 *
 */




#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CONFFILE "./rproxy.conf"
#define LOGFILENAME "./rproxy.log"

// Dla kompilacji na Linux'ie ustaw to na 0
#define HAVE_SIN_LEN 0

#define UID 65534
#define GID 65534
#define UMASK 0077
#define DEMON 1

#define DEFAULT_PORT 5080
#define BINDHOST "192.168.66.1"
#define MULTIPROC 0
#define MAXCLIENTS 10
#define UPLINK "217.113.224.30"
#define UPLINKPORT 6060

#define MAXLINELEN 200 // Linijki d³u¿sze bêd± uznawane, za nieprawid³owe
#define BUFSIZE 2048

#define INETLEN INET_ADDRSTRLEN

// Te znaki s± dozwolone w nag³ówku
#define DOBRE_ZNAKI \
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" \
"1234567890!@#$%^&*()_-+=\\|`~[]{};':\",.<>/?\r\n "



fd_set gniazda_r,wejscia,gniazda_w,wyjscia;
FILE *logfile=NULL;

typedef struct _wpis
{
	char *nazwa;
	char *wartosc; // Je¶li NULL, to wpis nie jest przekazywany do tunelu
} wpis;

wpis zmieniane_wpisy[]=
{ // Jakie pola w nag³ówkach zamieniaæ
	{"User-Agent","rproxy v0.0001 beta"},
	{"Appept-Language","pl,en"},
	{"Via",NULL},
	{NULL,NULL}
};


struct klientinfo
{
	int	fd; // deskryptor klienta
	int	tunfd; // deskryptor po³±czenia z nadrzêdnym proxy dla klienta
	struct sockaddr_in adres;
	int	dot_siz;
	char dotunelu[BUFSIZE];
	int	dok_siz;
	char doklienta[BUFSIZE];
	char headerline[MAXLINELEN];
	int ile;
	unsigned int	firstline:1;	// czy to pierwsza linijka nag³ówka? ( GET/POST/CONNECT itp. )
	unsigned int	exist:1;	// czy ten klient istnieje
} kl[MAXCLIENTS];

char *METODY[]={
	"GET",
	"POST",
	"HEAD",
	"CONNECT",
	NULL
};

int	clients,serwer_fd;

void	koniec(int);
void	plik_do_logowania(void);
int	wezlinie(struct klientinfo *,int);
int	przeslij(int,const char *,int);
void	skoncz_z_klientem(struct klientinfo *);
void	loguj(const char *, ...);
int	czysc_kl(struct klientinfo *,int);
void	blad(const char *,const char *, ...);
void	timestamp(time_t,char *,int);
void	demonizacja(void);

int main(argc,argv,env)
	int			argc;
	char**		argv;
	char**		env;
{
	int klient_fd,uplink_fd,fd,error;
	int ready,n,m,odczyt_n,iledanych;
	struct sockaddr_in sa1,tunaddr,klient;
	socklen_t len;
	char tempbuf[MAXLINELEN],*metoda,*url,*httpv;
	char *ptr;
	char optval[sizeof(SO_ERROR)];


	if( (serwer_fd=socket(AF_INET,SOCK_STREAM,0)) < 0 )
		err(EXIT_FAILURE,"socket()");

	bzero(&sa1,INETLEN);
#if defined(HAVE_SIN_LEN) && HAVE_SIN_LEN != 0
	sa1.sin_len=INETLEN;
#endif
	sa1.sin_family=AF_INET;
	sa1.sin_port=htons(DEFAULT_PORT);

	if( !(inet_aton(BINDHOST,&sa1.sin_addr)) )
		err(EXIT_FAILURE,"inet_aton()");

	while(1)
	{
		if( ! bind(serwer_fd,(struct sockaddr*)&sa1,INETLEN) )
			break;
		if( errno != EADDRINUSE )
			err(EXIT_FAILURE,"bin()");
		fprintf(stderr,"Adres i port serwera zajêty\nPonowna próba za 5 sekund...\n");
		sleep(5);
	}

	plik_do_logowania();

	// Obni¿enie przywilejów
	if( !getuid() )
	{
		if( setuid(UID) )
		{
			fprintf(stderr,"B³±d: Nie da³o siê zmieniæ UID (%d->%d)... (?!?)\n",getuid(),UID);
			err(EXIT_FAILURE,"setuid()");
		}
		printf("UID zmieniony na %d...\n",UID);
	}

	loguj("RPROXY uruchomione.\n");

	loguj("Serwer dzia³a na %s:%d.\n",BINDHOST,DEFAULT_PORT);

	signal(SIGTERM,koniec);
	signal(SIGINT,koniec);

	if( listen(serwer_fd,MAXCLIENTS) < 0 )
		blad("listen()",NULL);

	if( fcntl(serwer_fd,O_NONBLOCK) < 0 )
		blad("fcntl()",NULL);

	demonizacja();

	bzero(&tunaddr,INETLEN);
	bzero(&klient,INETLEN);

#if defined(HAVE_SIN_LEN) && HAVE_SIN_LEN != 0
	tunaddr.sin_len=INETLEN;
#endif
	tunaddr.sin_family=PF_INET;
	tunaddr.sin_port=htons(UPLINKPORT);
	if( !(inet_aton(UPLINK,&tunaddr.sin_addr)) )
		blad("inet_aton()",NULL);

	FD_ZERO(&wejscia);
	FD_ZERO(&wyjscia);
	FD_SET(serwer_fd,&wejscia);
	//	FD_SET(serwer_fd,&wyjscia);

	clients=0;
	czysc_kl(kl,MAXCLIENTS);

	for(;;)
	{
		gniazda_r=wejscia;
		gniazda_w=wyjscia;
		ready=select(MAXCLIENTS,&gniazda_r,&gniazda_w,(fd_set*)NULL,(struct timeval*)NULL);
		if( ready<0 )
			blad("B³±d1",NULL);
		if( !ready )
			continue;

		// Co¶ siê dzieje na gnie¼dzie serwerowym (pewnie nowy klient)
		if(FD_ISSET(serwer_fd,&gniazda_r))
		{
			--ready;
			len=INETLEN;
			if( (klient_fd=accept(serwer_fd,(struct sockaddr*)&klient,&len)) < 0 )
				blad("B³±d2",NULL);
			if(   len != INETLEN ||
#if defined(HAVE_SIN_LEN) && HAVE_SIN_LEN != 0
					klient.sin_len != INETLEN ||
#endif
					klient.sin_family != AF_INET )
			{
				if( close(klient_fd) < 0 )
					blad("close()",NULL);
				continue;
			}
			FD_SET(klient_fd,&wejscia);
			if( fcntl(klient_fd,O_NONBLOCK) < 0 )
				blad("B³±d3",NULL);

			// Znalezienie wolnego miejsca w tablicy klientów
			for(n=0;n<MAXCLIENTS;n++)
				if( ! kl[n].exist )
					break;

			if( n >= MAXLINELEN )
			{
				loguj("Maksymalna ilo¶æ klientów (%d) osi±gniêta.\n",MAXCLIENTS);
				skoncz_z_klientem(&kl[n]);
				continue;
			}

			kl[n].fd=klient_fd;
			kl[n].adres=klient;
			kl[n].firstline=1;
			kl[n].exist=1;
			kl[n].ile=0;
			++clients;

			loguj("Klient po³±czony z %s:%d\n",inet_ntoa(klient.sin_addr),ntohs(klient.sin_port));

			// Utworzenie po³±czenia z nadrzêdnym proxy dla tego klienta
			if( (uplink_fd=socket(PF_INET,SOCK_STREAM,0)) < 0 )
				blad("socket()",NULL);
			if( fcntl(uplink_fd,O_NONBLOCK) < 0 )
				blad("fcntl()",NULL);
			if( connect(uplink_fd,(const struct sockaddr*)&tunaddr,INETLEN) < 0 )
			{
				switch( errno )
				{
					case ECONNREFUSED:
						loguj("Nadrzêdne proxy nie uruchomione\n");
						strncpy(kl[n].doklienta,"Nadrzêdne proxy nie uruchomiowe\r\n",BUFSIZE);
						kl[n].dok_siz=strlen(kl[n].doklienta);
						if( !przeslij(klient_fd,kl[n].doklienta,kl[n].dok_siz) )
							continue;
						skoncz_z_klientem(&kl[n]);
						continue;
					case EINPROGRESS:
						FD_SET(uplink_fd,&wyjscia);
						break;
					default:
						blad("connect()",NULL);
				}
			}
			kl[n].tunfd=uplink_fd;
			//			FD_SET(uplink_fd,&wejscia);
		}

		// Czy który¶ klient co¶ nadaje?
		for( n=0 ; ( fd=kl[n].fd,n<MAXCLIENTS ) && ready ; n++ )
			if( kl[n].exist && FD_ISSET(fd,&gniazda_r) )
			{
				--ready;
				if( ioctl(fd,FIONREAD,&iledanych) < 0 )
					blad("B³±d7",NULL);
				if( !iledanych ) // Klient koñczy po³±czenie
					skoncz_z_klientem(&kl[n]);
				else{
					// Przetwarzamy nag³ówek
					error=wezlinie(&kl[n],iledanych);
					if( error <  0 )
						skoncz_z_klientem(&kl[n]);
					if( error <= 0 )
						continue;

					strncpy(tempbuf,kl[n].headerline,MAXLINELEN);
					tempbuf[kl[n].dot_siz]='\0';
					if(kl[n].firstline)
					{
						metoda=tempbuf;
						url=index(tempbuf,' ');
						if( ! url )
						{
							skoncz_z_klientem(&kl[n]);
							loguj("Nieznany format nag³ówka (ju¿ w pierwszej linijce)\n");
							continue;
						}
						*url++='\0';
						if( ! (httpv=index(url,' ')) )
						{
							skoncz_z_klientem(&kl[n]);
							loguj("Nieznany format nag³ówka (ju¿ w pierwszej linijce)\n");
							continue;
						}
						*httpv++='\0';
						for(m=0;METODY[m];m++)
							if( !strncmp(metoda,METODY[m],strlen(METODY[m])+1) )
								break;
						if( !METODY[m] )
						{
							skoncz_z_klientem(&kl[n]);
							loguj("Nieznana metoda\n");
							continue;
						}
						if( strncmp("HTTP/1.",httpv,7) || ( httpv[7]!='0' && httpv[7]!='1' ) )
						{
							skoncz_z_klientem(&kl[n]);
							loguj("Nieznany format nag³ówka (ju¿ w pierwszej linijce)\n");
							continue;
						}

						strncpy(kl[n].dotunelu,kl[n].headerline,kl[n].dot_siz);
						kl[n].firstline=0;
						przeslij(kl[n].tunfd,kl[n].dotunelu,kl[n].dot_siz);
						continue;
					}
					if( *tempbuf == '\n' || ( *tempbuf == '\r' && tempbuf[1] == '\n' ) ) // nag³ówek siê skoñczy³
					{
						strncpy(kl[n].dotunelu,"\r\n",2);
						kl[n].dot_siz=2;
						przeslij(kl[n].tunfd,kl[n].dotunelu,kl[n].dot_siz);
						FD_SET(kl[n].tunfd,&wejscia);
						kl[n].firstline=1;  // ..bo mo¿e to jest po³±czenie Keep-Alive
						continue;
					}
					ptr=index(tempbuf,':');
					if( !ptr )
					{
						// Jaki¶ syficzny nag³ówek, niech spada
						skoncz_z_klientem(&kl[n]);
						continue;
					}
					*ptr++='\0';
					for( m=0 ; zmieniane_wpisy[m].nazwa ; m++ )
						if( !strncasecmp(zmieniane_wpisy[m].nazwa,tempbuf,strlen(zmieniane_wpisy[m].nazwa)) )
						{
							if( !zmieniane_wpisy[m].wartosc )
								break; // Wpis usuniêty
							len=strlen(tempbuf) + 2 + strlen(zmieniane_wpisy[m].wartosc) + 1 + 1;
							if( BUFSIZE < len )
							{
								loguj("Zdefiniowany nag³ówek za d³ugi...\n");
								koniec(0);
							}
							strcpy(kl[n].dotunelu,tempbuf);
							strcat(kl[n].dotunelu,": ");
							strcat(kl[n].dotunelu,zmieniane_wpisy[m].wartosc);
							strcat(kl[n].dotunelu,"\r\n");

							przeslij(kl[n].tunfd,kl[n].dotunelu,len);
							break;
						}
					if( ! zmieniane_wpisy[m].nazwa )
						przeslij(kl[n].tunfd,kl[n].headerline,kl[n].dot_siz);
				}
			}

		// Który tunel co¶ nadaje ?
		for( n=0 ; ( fd=kl[n].tunfd,n<MAXCLIENTS ) && ready ; n++ )
			if( kl[n].exist && FD_ISSET(fd,&gniazda_r) )
			{
				--ready;
				if( ioctl(fd,FIONREAD,&odczyt_n) < 0 )
					blad("B³±d8",NULL);
				if( !odczyt_n )
				{ // Tunel zamkn±³ po³±czenie
					loguj(" Tunel zamkn±³ po³±czenie.\n");
					skoncz_z_klientem(&kl[n]);
					continue;
				}
				odczyt_n=read(fd,kl[n].doklienta,BUFSIZE);
				if( odczyt_n < 0 )
					switch( errno )
					{
						case EAGAIN:
							continue; // Raczej niemo¿liwe
						default:
							blad("read()",NULL);
					}
				kl[n].dok_siz=odczyt_n;
				przeslij(kl[n].fd,kl[n].doklienta,odczyt_n);
			}

		// Który tunel jest gotowy do pobierania danych ?
		for( n=0 ; ( fd=kl[n].tunfd,n<MAXCLIENTS ) && ready ; n++ )
			if( kl[n].exist && FD_ISSET(fd,&gniazda_w) )
			{
				--ready;
				if( getsockopt(fd,SOL_SOCKET,SO_ERROR,optval,&len) < 0 || len != sizeof(SO_ERROR) )
					blad("getsockopt()",NULL);
				switch( (int)*optval )
				{ // Czy w ogóle jest po³±czenie z tunelem ju¿ ustanowione ?
					case 0:
						/*
							if( ! FD_ISSET(fd,&gniazda_r) )
							FD_SET(fd,&wejscia);
							*/
						break; // Tak, jest
					case ECONNREFUSED:
						loguj("Nadrzêdne proxy nie uruchomione\n");
						przeslij(klient_fd,"Nadrzêdne proxy nie uruchomione\n",32);
						skoncz_z_klientem(&kl[n]);
						break;
					case EINPROGRESS:
						continue; // W toku
					default:
						blad("connect()",NULL);
				}

				if( przeslij(fd,kl[n].dotunelu,kl[n].dot_siz) )
					FD_CLR(fd,&wejscia);

			}

		// Który klient gotowy do pobierania danych
		for( n=0; ( fd=kl[n].fd,n<MAXCLIENTS ) && ready ; n++ )
			if( kl[n].exist && FD_ISSET(fd,&gniazda_w) && kl[n].dok_siz )
			{
				--ready;
				if( przeslij(fd,kl[n].doklienta,kl[n].dok_siz) )
					FD_CLR(fd,&wyjscia);
			}
	}
	exit(EXIT_SUCCESS);
}







void koniec(int sig)
{
	close(serwer_fd);
	loguj("RPROXY zakoñczy³o dzia³anie.\n");
	fclose(logfile);
	exit(EXIT_SUCCESS);
}

void plik_do_logowania(void)
{
	struct stat plikinfo;

	if( !lstat(LOGFILENAME,&plikinfo) && (plikinfo.st_mode&S_IFLNK) ==  S_IFLNK )
	{
		fprintf(stderr,"B³±d: Plik do logowania (%s) okaza³ siê symbolicznym linkiem [co mo¿e byæ gro¼ne].\n",LOGFILENAME);
		exit(EXIT_FAILURE);
	}

	if( access(LOGFILENAME,W_OK) )
		switch( errno )
		{
			case ENOTDIR:
				fprintf(stderr,"B³±d: Nie istnieje katalog, w którym mia³by siê znale¼æ plik z logami.\n"
						         "\t(%s)\n",LOGFILENAME);
				err(EXIT_FAILURE,"access()");
				break;
			case ENOENT:
				break;
			case EACCES:
				fprintf(stderr,"B³±d: Brak dostêpu do pliku z logami.\n\t(%s)\n",LOGFILENAME);
				err(EXIT_FAILURE,"access()");
				break;
			default:
				err(EXIT_FAILURE,"access()");
		}

	umask(UMASK);
	logfile=fopen(LOGFILENAME,"a");
	if( !logfile )
	{
		fprintf(stderr,"B³±d: Nie da³o siê otworzyæ pliku %s do zapisu.\n",LOGFILENAME);
		err(EXIT_FAILURE,"fopen()");
	}


}

int wezlinie(struct klientinfo *a,int ile)
	// Zwraca:
	// -1			b³±d
	//  0			ok, ale nie ma \n
	//  1			ok, jest ca³a linia
{
	int max,*ile_danych;
	int n=0;
	char znak='\0';

	ile_danych=&a->ile;
	max = ile<MAXLINELEN ? ile : MAXLINELEN;

	while( znak != '\n' && *ile_danych < max )
	{
		if( read(a->fd,&znak,1) != 1 )
			blad("read()",NULL);
		a->headerline[*ile_danych]=znak;
		++*ile_danych;
	}


	if( strspn(a->headerline,DOBRE_ZNAKI) < *ile_danych )
	{
		loguj(" Klient %s przes³a³ podejrzane znaki\n",inet_ntoa(a->adres.sin_addr));
		return -1;
	}

	if( znak == '\n' )
	{
		a->dot_siz = *ile_danych;
		*ile_danych=0;
		return 1;
	}

	if( *ile_danych == MAXLINELEN )
	{
		a->headerline[MAXLINELEN-2]='\r';
		a->headerline[MAXLINELEN-1]='\n';
		// Wyczyszczenie reszty w linijce
		for( n=0,znak='\0' ; znak != '\n' && n<ile-MAXLINELEN ; n++ )
			read(a->fd,&znak,1);
		loguj(" Bardzo d³uga linia w nag³ówku (%d znaków), mo¿e zwiêksz MAXLINELEN ?\n",*ile_danych+n);
		loguj(" Linia obciêta do d³ugo¶ci MAXLINELEN (%d)\n",MAXLINELEN);
		if( znak == '\n' )
		{
			a->dot_siz = *ile_danych;
			*ile_danych=0;
			return 1;
		}
		return -1;
	}
	return 0;

}

int przeslij(int desc,const char *dane,int rozmiar)
// Zwraca 1, gdy OK. Zwraca 0, gdy deskryptor jest nieblokuj±cy i nie mo¿na by³o zapisaæ
{
	int zapisano;

	if( (zapisano=write(desc,dane,rozmiar)) < 0 )
		if( errno == EAGAIN )
		{
			FD_SET(desc,&wyjscia);
			return 0;
		}else
			blad("write()",NULL);
		else if( zapisano != rozmiar )
			blad("write()",NULL);
	return 1;
}

void skoncz_z_klientem(struct klientinfo* klient)
{
	--clients;
	FD_CLR(klient->fd,&wejscia);
	FD_CLR(klient->fd,&wyjscia);
	FD_CLR(klient->tunfd,&wejscia);
	FD_CLR(klient->tunfd,&wyjscia);
	klient->exist=0;
	close(klient->fd);
	close(klient->tunfd);
	loguj("Po³±czenie z klientem %s:%d zakoñczone.\n",inet_ntoa(klient->adres.sin_addr),ntohs(klient->adres.sin_port));
}

void loguj(const char *fmt, ...)
{
	va_list ap;
	int len;
	char bufor[23];
	char errmsg[]="B³±d: Nie da³o siê zapisaæ do pliku z logami...(?)\n";

	timestamp((time_t)NULL,bufor,23);
	len=strlen(bufor);
	if( fwrite(bufor,1,len,logfile) != len )
		blad("fwrite()",errmsg);

#if !defined(DEMON) || DEMON == 0
	printf("%s",bufor);
#endif

	va_start(ap,fmt);
	vfprintf(logfile,fmt,ap);
#if !defined(DEMON) || DEMON == 0
	vprintf(fmt,ap);
#endif
	va_end(ap);

	if( fsync(fileno(logfile)) )
		blad("fsync()",errmsg);

}

int czysc_kl(struct klientinfo *a,int ile)
{
	int n;

	for(n=0;n<ile;n++)
		a[n].exist=0;

	return 0;
}

void blad(const char* gdzie,const char *tresc, ...)
{
	va_list ap;
	int __errno=errno;
	char bufor[23];

	close(serwer_fd);
	if( tresc )
	{
		timestamp((time_t)NULL,bufor,23);
		fprintf(logfile,"%s",bufor);

		va_start(ap,tresc);
		vfprintf(logfile,tresc,ap);
#if !defined(DEMON) || DEMON == 0
		vfprintf(stderr,tresc,ap);
#endif
		va_end(ap);

	}
	if( logfile )
		fclose(logfile);

	errno = __errno;
	err(EXIT_FAILURE,gdzie);
}

void timestamp(time_t t,char *bufor,int len)
{
	struct tm czas;
	time_t tt;

	tt = t ? t : time(NULL);
	czas = *localtime(&tt);
	strftime(bufor,len,"[%d/%m/%Y %H:%M:%S] ",&czas);
	bufor[len-1]='\0';
}

void demonizacja(void)
{
	pid_t pid;

	pid=fork();
	if( pid < 0 )
		blad("fork()","B³±d: Proces nie móg³ staæ siê demonem.\n");
	else if( pid )
	{
		sleep(1);
		exit(EXIT_SUCCESS);
	}
	if( setsid() < 0 )
		blad("fork()","B³±d: Proces nie móg³ staæ siê demonem.\n");
	if( chdir("/") < 0 )
		blad("chdir()","B³±d: Nie da³o siê zmieniæ katalogu na: /\n");
	printf("Proces sta³ siê demonem. Pid procesu: %d\n",getpid());
	close(0);
	close(1);
	close(2);
}

