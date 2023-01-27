#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>


#define CRL_UP_TO_DATE 1
#define CRL_NOT_UP_TO_DATE 0
#define OID_CRL_NEXT_PUBLISH "1.3.6.1.4.1.311.21.4"

void check_date(struct tm *date) {
	time_t now = time(NULL);
	time_t next_update_time_t = mktime(date);
	double delta_seconds = difftime(now, next_update_time_t);
	int delta_seconds_abs, up_to_date;
	if (delta_seconds > 0) {
		delta_seconds_abs = (int)delta_seconds;
		up_to_date = CRL_NOT_UP_TO_DATE;
	}
	else {
		delta_seconds_abs = (int)fabs(delta_seconds);
		up_to_date = CRL_UP_TO_DATE;
	}

	int days = (int)(delta_seconds_abs/86400);
	int hours = (int)((delta_seconds_abs - days * 86400)/3600);
	int minutes = (int)((delta_seconds_abs - days * 86400 - hours * 3600)/60);
	int seconds = (int)(delta_seconds_abs - days * 86400 - hours * 3600 - minutes * 60);

	switch(up_to_date) {
		case 0:
			if (days > 0)
				printf("!!! / ! \\ CRL NON A JOUR / ! \\ !!!. La CRL n'est plus a jour depuis %d jours.\n", days);
			else if (hours > 0)
				printf("!!! / ! \\ CRL NON A JOUR / ! \\ !!!. La CRL n'est plus a jour depuis %d heures.\n,", hours);
			else if (minutes > 0)
				printf("!!! / ! \\ CRL NON A JOUR / ! \\ !!!. La CRL n'est plus a jour depuis %d minutes.\n", minutes);
			else
				printf("!!! / ! \\ CRL NON A JOUR / ! \\ !!!. La CRL n'est plus a jour depuis %d secondes.\n", seconds);
			break;
		case 1:
			if (days > 0 && up_to_date)
				printf("CRL A JOUR. La prochaine sera publiee dans %d jours.\n", days);
			else if (hours > 0 && up_to_date)
				printf("CRL A JOUR. La prochaine sera publiée dans %d heures.\n,", hours);
			else if (minutes > 0 && up_to_date)
				printf("CRL A JOUR. La prochaine sera publiee dans %d minutes.\n", minutes);
			else
				printf("CRL A JOUR. La prochaine sera publiee dans %d secondes.\n", seconds);
			break;
	}
}

int ReadHttpStatus(int sock){
	char c;
	char buff[1024]="",*ptr=buff+1;
	int bytes_received, status;
	while(bytes_received = recv(sock, ptr, 1, 0)){
		if(bytes_received==-1){
			perror("ReadHttpStatus");
			exit(1);
		}

		if((ptr[-1]=='\r')  && (*ptr=='\n' )) break;
		ptr++;
	}
	*ptr=0;
	ptr=buff+1;
	sscanf(ptr,"%*s %d ", &status);
	return (bytes_received>0)?status:0;

}

//the only filed that it parsed is 'Content-Length'
int ParseHeader(int sock){
	char c;
	char buff[1024]="",*ptr=buff+4;
	int bytes_received, status;
	while(bytes_received = recv(sock, ptr, 1, 0)){
		if(bytes_received==-1){
			perror("Parse Header");
			exit(1);
		}

		if(
				(ptr[-3]=='\r')  && (ptr[-2]=='\n' ) &&
				(ptr[-1]=='\r')  && (*ptr=='\n' )
		  ) break;
		ptr++;
	}

	*ptr=0;
	ptr=buff+4;

	if(bytes_received){
		ptr=strstr(ptr,"Content-Length:");
		if(ptr){
			sscanf(ptr,"%*s %d",&bytes_received);

		}else
			bytes_received=-1; //unknown size

	}
	return  bytes_received ;

}

void download_file(char *splitted_url[]){
	char *domain = splitted_url[1];
	char path[100];
	snprintf(path, sizeof(path), "%s/%s", splitted_url[2], splitted_url[3]);
	int sock, bytes_received;
	char send_data[1024],recv_data[1024], *p;
	struct sockaddr_in server_addr;
	struct hostent *he;


	he = gethostbyname(domain);
	if (he == NULL){
		herror("gethostbyname");
		exit(1);
	}

	if ((sock = socket(AF_INET, SOCK_STREAM, 0))== -1){
		perror("Socket");
		exit(1);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(80);
	server_addr.sin_addr = *((struct in_addr *)he->h_addr);
	bzero(&(server_addr.sin_zero),8);

	if (connect(sock, (struct sockaddr *)&server_addr,sizeof(struct sockaddr)) == -1){
		perror("Connect");
		exit(1);
	}


	snprintf(send_data, sizeof(send_data), "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", path, domain);

	if(send(sock, send_data, strlen(send_data), 0)==-1){
		perror("send");
		exit(2);
	}
	int contentlengh;

	if(ReadHttpStatus(sock) && (contentlengh=ParseHeader(sock))){

		int bytes=0;
		FILE* fd=fopen(splitted_url[3],"wb");

		while(bytes_received = recv(sock, recv_data, 1024, 0)){
			if(bytes_received==-1){
				perror("recieve");
				exit(3);
			}
			fwrite(recv_data,1,bytes_received,fd);
			bytes+=bytes_received;
			if(bytes==contentlengh)
				break;
		}
		fclose(fd);
	}

	close(sock);
}


int check_crl(const char crl_filestr[], int ms_nid) {
	BIO                 *crlbio = NULL;
	BIO                 *outbio = NULL;
	X509_CRL            *mycrl  = NULL;
	const STACK_OF(X509_EXTENSION) *exts;
	X509_REVOKED     *rev_entry = NULL;
	ASN1_STRING *extvalue = NULL;
	const ASN1_TIME *last_update, *next_update;
	struct tm *next_update_time = NULL;
	struct tm *oid_ms_date = NULL;
	int ms_idx;
	char asn1_date_str[15];

	// ALLOCATION MEMOIRE DES POINTEURS
	next_update_time = malloc(sizeof(*next_update_time));	
	oid_ms_date = malloc(sizeof(*oid_ms_date));
	extvalue = malloc(sizeof(*extvalue));

	/* ---------------------------------------------------------- *
	 * These function calls initialize openssl for correct work.  *
	 * ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* ---------------------------------------------------------- *
	 * Create the Input/Output BIO's.                             *
	 * ---------------------------------------------------------- */
	crlbio = BIO_new(BIO_s_file());
	outbio = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* ---------------------------------------------------------- *
	 *  Load the certificate revocation list from file (DER).      *
	 *  ---------------------------------------------------------- */
	if (BIO_read_filename(crlbio, crl_filestr) <= 0)
		BIO_printf(outbio, "Error loading cert into memory\n");

	mycrl = d2i_X509_CRL_bio(crlbio, NULL);

	/* ---------------------------------------------------------- *
	 * Get Extensions                                             * 					      
	 * ---------------------------------------------------------- */

	// ms_nid = OBJ_create(OID_CRL_NEXT_PUBLISH, "NextPublish", "New Object Identifier");
	exts = X509_CRL_get0_extensions(mycrl);
	if(sk_X509_EXTENSION_num(exts) <= 0)
		printf("La CRL ne contient pas d'extension");

	ms_idx = X509_CRL_get_ext_by_NID(mycrl, ms_nid, -1);
	if (ms_idx > 0) {
		X509_EXTENSION *ex = X509_CRL_get_ext(mycrl, ms_idx);
		extvalue = X509_EXTENSION_get_data(ex);
		const unsigned char *ms_time_str = ASN1_STRING_get0_data(extvalue);

		strncpy(asn1_date_str, ms_time_str, 15); 
		asn1_date_str[14] = '\0';

		// variables 
		char date[6][5];
		for (int i=1; i<7; i++) {
			for (int j=0; j<5;j++) {
				if (i==1){
					date[0][0] = '2';
					date[0][1] = '0';
					date[i-1][4] = '\0';
					date[i-1][j+2] = (char)asn1_date_str[i+j+i];
				}else{
					date[i-1][2] = '\0';
					date[i-1][j] = (char)asn1_date_str[i+j+i];
				}
			}
		}

		if (ms_time_str == NULL)
			printf("Impossible de recupere la date dans la memoire tampom");

		// forging of time_t
		oid_ms_date->tm_mday = atoi(date[2]);
		oid_ms_date->tm_mon = atoi(date[1])-1;  
		oid_ms_date->tm_year = atoi(date[0]) - 1900;
		oid_ms_date->tm_hour = atoi(date[3]);
		oid_ms_date->tm_min = atoi(date[4]);
		oid_ms_date->tm_sec = atoi(date[5]);
		check_date(oid_ms_date);

		if (ex == NULL)
			printf("Impossible de charger l'extension en memoire");
	}
	else {
		/* ---------------------------------------------------------- *
		 * Print the CRL Next Release Date and Time (may not exist)   *
		 * ---------------------------------------------------------- */
		if (next_update = X509_CRL_get0_nextUpdate(mycrl)) {
			if (ASN1_TIME_to_tm(next_update, next_update_time)) {
				check_date(next_update_time);
			}
		}
	}
	OBJ_cleanup();
	free(next_update_time);
	free(oid_ms_date);
	free(rev_entry);
}
int main(void){
	int ret;
	int ms_nid = OBJ_create(OID_CRL_NEXT_PUBLISH, "NextPublish", "New Object Identifier");
	// LISTE DES URL DES CRL
	char urls[18][100] = {
		// URL CHAR* ARRAY
	};

	for (int i=0; i <18 ; i++) {
		char *splitted_url[4];
		char *ptr = strtok(urls[i], "/");
		int idx = 0;
		while (ptr != NULL)
		{
			splitted_url[idx++] = ptr;
			ptr = strtok(NULL, "/");
		}
		download_file(splitted_url);
		printf("Vérification pour %s\n", splitted_url[2]);
		check_crl(splitted_url[3], ms_nid);
		ret = remove(splitted_url[3]);
		if (ret != 0)
			printf("Impossible de supprimer le fichier CRL : %s\n", splitted_url[3]);

	}
}
