#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>

bool check(const char* allowedFingerprintsFilePath, const char* digest);

const size_t DIGEST_LENGTH = 95;

int main(int argc, char *argv[]) {
	if(argc!=4) {
		printf("Usage: %s <allowed_fingerprints_file_path> <certificate_depth> <subject>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	const char* allowedFingerprintsFilePath = argv[1];
	const char* certificateDepth = argv[2];

	if(strcmp(certificateDepth, "0")!=0) {
		printf("Current certificate_depth is %s, exiting...\n", argv[1]);
		exit(EXIT_SUCCESS);
	}

	const char* cn = getenv("X509_0_CN");
	const char* digest = getenv("tls_digest_sha256_0");

	syslog(LOG_INFO, "cn=%s, digest=%s", cn, digest);

	if(strlen(digest)!=DIGEST_LENGTH) {
		syslog(LOG_WARNING, "Digest of %s has invalid length!", cn);
		exit(EXIT_FAILURE);
	}

	if(check(allowedFingerprintsFilePath, digest) == true) {
		syslog(LOG_INFO, "Successfully checked digest of %s", cn);
		exit(EXIT_SUCCESS);
	} else {
		syslog(LOG_WARNING, "Digest of %s is not allowed: %s", cn, digest);
		exit(EXIT_FAILURE);
	}
}

bool check(const char* allowedFingerprintsFilePath, const char* digest) {
	FILE * fp;
    	char * line = NULL;
    	size_t len = 0;
    	
	fp = fopen(allowedFingerprintsFilePath, "r");
    	
	if (fp == NULL) {
		syslog(LOG_ERR, "Failed to open file %s", allowedFingerprintsFilePath);
        	exit(EXIT_FAILURE);
	}

    	while (getline(&line, &len, fp) != -1) {
        	if(strncmp(line, digest, DIGEST_LENGTH)==0) {
			return true;
		}
	}
	
	fclose(fp);

	return false;
}