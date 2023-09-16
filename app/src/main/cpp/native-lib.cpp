#include <jni.h>
#include <string>
#include <android/log.h>
//#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#define TAG "MY_TAG"

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,    TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,     TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,     TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,    TAG, __VA_ARGS__)

#include<iostream>
#include <stdio.h>
#include <string.h>
#include <cstdio>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>

//TAG947: START: length in bytes
#define MD5LEN 16
#define SHA1LEN 20
#define SHA256LEN 32
#define SHA512LEN 64

const int DEBUG = 0;
//TAG947: END

//TAG947: START >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>START OF OPENSSL AND OTHER UTIL FUNCTIONS>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>//
const char* get_subject_name(X509* cert)// for finding the subject name, currently not used
{
    const char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    return subj;
}
const char* get_issuer_name(X509* cert) // for finding the serial number, currently not used
{
    const char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    return issuer;
}
// used for computing sha values for Public Keys
unsigned char *get_pubkey_sha1(X509* cert)
{
    unsigned char *derEncodedPkey = NULL;
    char* base64Hash = NULL;
    EVP_PKEY *pubkey;
    int pubkeylen;
    // 1. get the public key
    pubkey = X509_get_pubkey(cert);
    if (!pubkey) // failed to parse certificate
        return NULL;

    // 2. convert pubkey to der encoding
    pubkeylen = i2d_PUBKEY(pubkey, &derEncodedPkey);
    // 3. free EVP_PKEY after we get the bytes from it
    EVP_PKEY_free(pubkey);
    // 4. allocate context and hash buffer for storing sha value
    SHA_CTX ctx;
    int SHALEN = SHA1LEN;
    unsigned char *hash = (unsigned char*)malloc(SHALEN* sizeof(unsigned char));

    // 5. compute sha value
    if (!SHA1_Init(&ctx))
        goto die;
    if (!SHA1_Update(&ctx, derEncodedPkey, pubkeylen))
        goto die;
    if (!SHA1_Final(hash, &ctx))
        goto die;
    // 6. free derEncodedPkey after we get the hash from it
    free(derEncodedPkey);

    // 7. return computed sha value
    return hash;
    die:
    free(derEncodedPkey); // alternative if there's any weird error, we are still freeing derEncodedPkey
    LOGE("PubKey: SHA-1 hash failed");
    return NULL;
}

// used for computing sha values for Public Keys
unsigned char *get_pubkey_sha256(X509* cert)
{
    unsigned char *derEncodedPkey = NULL;
    char* base64Hash = NULL;
    EVP_PKEY *pubkey;
    int pubkeylen;
    // 1. get the public key
    pubkey = X509_get_pubkey(cert);
    if (!pubkey) // failed to parse certificate
        return NULL;

    // 2. convert pubkey to der encoding
    pubkeylen = i2d_PUBKEY(pubkey, &derEncodedPkey);
    // 3. free EVP_PKEY after we get the bytes from it
    EVP_PKEY_free(pubkey);
    // 4. allocate context and hash buffer for storing sha value
    SHA256_CTX ctx;
    int SHALEN = SHA256LEN;
    unsigned char *hash = (unsigned char*)malloc(SHALEN* sizeof(unsigned char));

    // 5. compute sha value
    if (!SHA256_Init(&ctx))
        goto die;
    if (!SHA256_Update(&ctx, derEncodedPkey, pubkeylen))
        goto die;
    if (!SHA256_Final(hash, &ctx))
        goto die;
    // 6. free derEncodedPkey after we get the hash from it
    free(derEncodedPkey);

    // 7. return computed sha value
    return hash;
    die:
    free(derEncodedPkey); // alternative if there's any weird error, we are still freeing derEncodedPkey
    LOGE("PubKey: SHA-256 hash failed");
    return NULL;
}

// used for computing sha values for Public Keys
unsigned char *get_pubkey_sha512(X509* cert)
{
    unsigned char *derEncodedPkey = NULL;
    char* base64Hash = NULL;
    EVP_PKEY *pubkey;
    int pubkeylen;
    // 1. get the public key
    pubkey = X509_get_pubkey(cert);
    if (!pubkey) // failed to parse certificate
        return NULL;

    // 2. convert pubkey to der encoding
    pubkeylen = i2d_PUBKEY(pubkey, &derEncodedPkey);
    // 3. free EVP_PKEY after we get the bytes from it
    EVP_PKEY_free(pubkey);
    // 4. allocate context and hash buffer for storing sha value
    SHA512_CTX ctx;
    int SHALEN = SHA512LEN;
    unsigned char *hash = (unsigned char*)malloc(SHALEN* sizeof(unsigned char));

    // 5. compute sha value
    if (!SHA512_Init(&ctx))
        goto die;
    if (!SHA512_Update(&ctx, derEncodedPkey, pubkeylen))
        goto die;
    if (!SHA512_Final(hash, &ctx))
        goto die;
    // 6. free derEncodedPkey after we get the hash from it
    free(derEncodedPkey);

    // 7. return computed sha value
    return hash;
    die:
    free(derEncodedPkey); // alternative if there's any weird error, we are still freeing derEncodedPkey
    LOGE("PubKey: SHA-512 hash failed");
    return NULL;
}


unsigned char* get_sha1(X509* cert, int granularity) // for finding sh1 of certificate signature or pkey
{
    if(granularity == 1){
        /*Granularity = 1 --> Uploading a public key of a leaf certificate*/
        return get_pubkey_sha1(cert);
    }

    /*Granularity = 0 --> Uploading a leaf certificate*/
    const EVP_MD *digest = EVP_sha1();
    unsigned char* buf = (unsigned char*) malloc(SHA1LEN * sizeof(unsigned char));
    unsigned len;
    int rc = X509_digest(cert, digest, (unsigned char*)buf, &len);
    if(rc == 0 || len != SHA1LEN /*SHA1LEN*/){
        return NULL;
    }
    return buf;
}
unsigned char* get_sha256(X509* cert, int granularity) // for finding sha256 of certificate signature or pkey
{
    if(granularity == 1){
        /*Granularity = 1 --> Uploading a public key of a leaf certificate*/
        return get_pubkey_sha256(cert);
    }
    /*Granularity = 0 --> Uploading a leaf certificate*/
    const EVP_MD *digest = EVP_sha256();
    unsigned char* buf = (unsigned char*) malloc(SHA256LEN * sizeof(unsigned char));
    unsigned len;
    int rc = X509_digest(cert, digest, (unsigned char*)buf, &len);
    if(rc == 0 || len != SHA256LEN /*SHA256LEN*/){
        return NULL;
    }
    return buf;
}
unsigned char* get_sha512(X509* cert, int granularity) // for finding sha512 of certificate signature or pkey
{
    if(granularity == 1){
        /*Granularity = 1 --> Uploading a public key of a leaf certificate*/
        return get_pubkey_sha512(cert);
    }
    /*Granularity = 0 --> Uploading a leaf certificate*/
    const EVP_MD *digest = EVP_sha512();
    unsigned char* buf = (unsigned char*) malloc(SHA512LEN * sizeof(unsigned char));
    unsigned len;
    int rc = X509_digest(cert, digest, (unsigned char*)buf, &len);
    if(rc == 0 || len != SHA512LEN /*SHA512LEN*/){
        return NULL;
    }
    return buf;
}

void hex_encode(unsigned char* readbuf, void *writebuf, size_t len){ // hex encoding for printing, output othis is not the real hex signature, but a printable one
    for(size_t i=0; i < len; i++) {
        char *l = (char*) (2*i + ((intptr_t) writebuf));
        sprintf(l, "%02x", readbuf[i]);
    }
}
int get_version(X509* cert) /*For parsing version number*/
{
    return ((int)X509_get_version(cert))+1;
}

#define DATE_LEN 128
int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len)
{
    int rc;
    BIO *b = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(b, t);
    if (rc <= 0) {
            LOGE("ASN1_TIME_print failed or wrote no data.\n");
        BIO_free(b);
        return EXIT_FAILURE;
    }
    rc = BIO_gets(b, buf, len);
    if (rc <= 0) {
        LOGE("BIO_gets call failed to transfer contents to buf");
        BIO_free(b);
        return EXIT_FAILURE;
    }
    BIO_free(b);
    return EXIT_SUCCESS;
}

int current_time_in_cert_validation_period(X509* cert)
{
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    time_t current_rawtime;
    time(&current_rawtime);
    ASN1_TIME *current_time = ASN1_TIME_set(NULL, current_rawtime);
    if(
            X509_cmp_time(not_before, &current_rawtime) == -1
            &&												/*See X509_cmp_time() documentation in openssl docs*/
            X509_cmp_time(not_after, &current_rawtime) == 1
            )
        return 1;
    return 0;
}


void printShaValues(X509 *cert)
{

    // usage: remember to free after use, specially for get_shaX type function, the space is allocated in local function, but need to be freed after use
    unsigned char* sha1_cert = get_sha1(cert, 0);
    unsigned char* sha1_pubk = get_sha1(cert, 1);

    unsigned char* sha256_cert = get_sha256(cert, 0);
    unsigned char* sha256_pubk = get_sha256(cert, 1);

    unsigned char* sha512_cert = get_sha512(cert, 0);
    unsigned char* sha512_pubk = get_sha512(cert, 1);

    char* hash_hex_sha1 = (char *)malloc((2*SHA1LEN+1)*sizeof(char));
    char* hash_hex_sha256 = (char *)malloc((2*SHA256LEN+1)*sizeof(char));
    char* hash_hex_sha512 = (char *)malloc((2*SHA512LEN+1)*sizeof(char));

    int base64len_sha1 = 4*((SHA1LEN+2)/3);
    int base64len_sha256 = 4*((SHA256LEN+2)/3);
    int base64len_sha512 = 4*((SHA512LEN+2)/3);

    char* hash_base64_sha1 = (char *)malloc((base64len_sha1+1)*sizeof(char));
    char* hash_base64_sha256 = (char *)malloc((base64len_sha256+1)*sizeof(char));
    char* hash_base64_sha512 = (char *)malloc((base64len_sha512+1)*sizeof(char));


    if(DEBUG)
        LOGI("\n\nSHA-1:\n");

    hex_encode(sha1_cert, hash_hex_sha1, SHA1LEN);
    EVP_EncodeBlock((unsigned char *)hash_base64_sha1, sha1_cert, SHA1LEN);
    hash_hex_sha1[(2*SHA1LEN)+1] = '\0';
    hash_base64_sha1[base64len_sha1+1] = '\0';
    if(DEBUG)
        LOGI("CERT_HEX: %s\n", hash_hex_sha1);
    if(DEBUG)
        LOGI("CERT_BASE64: %s\n", hash_base64_sha1);

    hex_encode(sha1_pubk, hash_hex_sha1, SHA1LEN);
    EVP_EncodeBlock((unsigned char *)hash_base64_sha1, sha1_pubk, SHA1LEN);
    hash_hex_sha1[(2*SHA1LEN)+1] = '\0';
    hash_base64_sha1[base64len_sha1+1] = '\0';
    if(DEBUG)
        LOGI("PUBK_HEX: %s\n", hash_hex_sha1);
    if(DEBUG)
        LOGI("PUBK_BASE64: %s\n", hash_base64_sha1);



    if(DEBUG)
        LOGI("\n\nSHA-256:\n");

    hex_encode(sha256_cert, hash_hex_sha256, SHA256LEN);
    EVP_EncodeBlock((unsigned char *)hash_base64_sha256, sha256_cert, SHA256LEN);
    hash_hex_sha256[(2*SHA256LEN)+1] = '\0';
    hash_base64_sha256[base64len_sha256+1] = '\0';
    if(DEBUG)
        LOGI("CERT_HEX: %s\n", hash_hex_sha256);
    if(DEBUG)
        LOGI("CERT_BASE64: %s\n", hash_base64_sha256);

    hex_encode(sha256_pubk, hash_hex_sha256, SHA256LEN);
    EVP_EncodeBlock((unsigned char *)hash_base64_sha256, sha256_pubk, SHA256LEN);
    hash_hex_sha256[(2*SHA256LEN)+1] = '\0';
    hash_base64_sha256[base64len_sha256+1] = '\0';

    if(DEBUG)
        LOGI("PUBK_HEX: %s\n", hash_hex_sha256);
    if(DEBUG)
        LOGI("PUBK_BASE64: %s\n", hash_base64_sha256);

    if(DEBUG)
        LOGI("\n\nSHA-512:\n");

    hex_encode(sha512_cert, hash_hex_sha512, SHA512LEN);
    EVP_EncodeBlock((unsigned char *)hash_base64_sha512, sha512_cert, SHA512LEN);
    hash_hex_sha512[(2*SHA512LEN)+1] = '\0';
    hash_base64_sha512[base64len_sha512+1] = '\0';
    if(DEBUG)
        LOGI("CERT_HEX: %s\n", hash_hex_sha512);
    if(DEBUG)
        LOGI("CERT_BASE64: %s\n", hash_base64_sha512);

    hex_encode(sha512_pubk, hash_hex_sha512, SHA512LEN);
    EVP_EncodeBlock((unsigned char *)hash_base64_sha512, sha512_pubk, SHA512LEN);
    hash_hex_sha512[(2*SHA512LEN)+1] = '\0';
    hash_base64_sha512[base64len_sha512+1] = '\0';

    if(DEBUG)
        LOGI("PUBK_HEX: %s\n", hash_hex_sha512);
    if(DEBUG)
        LOGI("PUBK_BASE64: %s\n", hash_base64_sha512);

}

int wpa_supplicant_qr_verify_certificate(int certValid, const char* hash, const char* hashList, const jint* cumHashSize, unsigned int cumHashSizeLen)
{
    int success_fingerprint = 0;

    int j, k;
    int lenq = -1;
    int tmp = 0;
    for(int i=0; i < cumHashSizeLen; i++){
        tmp = 1;
        if(i==0)
            lenq = cumHashSize[i];
        else
            lenq = cumHashSize[i] - cumHashSize[i-1];

        if(lenq == strlen(hash)){
            if(i == 0)
                j = 0;
            else
                j = cumHashSize[i-1];
            k = 0;
            while(j<cumHashSize[i]){
                if(hashList[j] == hash[k]){
                    j++;k++;
                }
                else{
                    tmp = 0;
                    break;
                }
            }
        }
        if(tmp){
            if(i == 0)
                j = 0;
            else
                j = cumHashSize[i-1];
            if(DEBUG)
                LOGI("TAG947: wpa_supplicant_qr_verify_certificate(): MATCH success@: %d %.*s", i, lenq, hashList+j);
            success_fingerprint = 1;
            break;
        }else{
            if(DEBUG)
                LOGI("TAG947: wpa_supplicant_qr_verify_certificate(): MATCH failed@: %d %.*s", i, lenq, hashList+j);
        }
    }



    if(success_fingerprint && certValid)
        return 3; /*1 1*/
    else if(success_fingerprint && !certValid)
        return 2; /*1 0*/
    else if (!success_fingerprint && certValid)
        return 1; /*0 1*/
    else if (!success_fingerprint && !certValid)
        return 0; /*0 0*/

    return -1; // shouldn't reach
}

int tls_verify_cb(X509* err_cert, int granularity, int hashChoice, const char* hashList, jint* cumHashSize, unsigned int cumHashSizeLen)
{

    if(DEBUG)
        LOGI("TAG947: INSIDE DEPTH 0: LEAF CERTIFICATE!");
    int preverify_ok = 1;
    int base64len = 0;
    char *hash_hex = 0;
    unsigned char *shaValue = 0;
    char *hash_base64 = 0;

    if(DEBUG)
        LOGI("TAG947: Got info in tls_verify_cb(): granularity: %d, hashChoice: %d", granularity, hashChoice);

    switch(hashChoice){
        case 0: /*SHA256*/
            base64len = 4*((SHA256LEN+2)/3);

            hash_base64 = (char *)malloc((base64len+1)*sizeof(char));
            hash_hex = (char *)malloc((2*SHA256LEN+1)*sizeof(char));
            shaValue = get_sha256(err_cert, granularity);

            if(shaValue){

                hex_encode(shaValue, hash_hex, SHA256LEN);
                int ol = EVP_EncodeBlock((unsigned char *)hash_base64, shaValue, SHA256LEN);

                if(ol!=base64len){
                    LOGE("TAG947: SHA256:Weird error when calculating using EVP_EncodeBlock: %s", hash_base64);
                }

                hash_hex[(2*SHA256LEN)+1] = '\0';
                hash_base64[base64len+1] = '\0';
            }else{
                //clear out the buffer
                hash_hex[0] = '\0';
                hash_base64[0]='\0';
                LOGE("TAG947: SHA256:Error parsing signature from the certificate in tls_verify_cb()");
            }
            break;
        case 1: /*SHA512*/
            base64len = 4*((SHA512LEN+2)/3);

            hash_base64 = (char *)malloc((base64len+1)*sizeof(char));
            hash_hex = (char *)malloc((2*SHA512LEN+1)*sizeof(char));
            shaValue = get_sha512(err_cert, granularity);

            if(shaValue){

                hex_encode(shaValue, hash_hex, SHA512LEN);
                int ol = EVP_EncodeBlock((unsigned char *)hash_base64, shaValue, SHA512LEN);

                if(ol!=base64len){
                    LOGE("TAG947: SHA512:Weird error when calculating using EVP_EncodeBlock: %s", hash_base64);
                }

                hash_hex[(2*SHA512LEN)+1] = '\0';
                hash_base64[base64len+1] = '\0';
            }else{
                //clear out the buffer
                hash_hex[0] = '\0';
                hash_base64[0]='\0';
                LOGE("TAG947: SHA512:Error parsing signature from the certificate in tls_verify_cb()");
            }
            break;
        default:
            LOGE("TAG947: INVALID HASH CHOICE in tls_verify_cb()");
            break;
    }


    if(DEBUG)
        LOGI("TAG947: Hash_hex --> %s",hash_hex);
    if(DEBUG)
        LOGI("TAG947: Hash_base64 --> %s", hash_base64);



    int certValid = 1; // ignore the period validity if granularity is 1
    if(granularity == 0) // use it if granularity is 0
        certValid = current_time_in_cert_validation_period(err_cert); // NOTE: used only if we want to make sure the certificate is valid in the period

    preverify_ok = wpa_supplicant_qr_verify_certificate(certValid, hash_base64, hashList, cumHashSize, cumHashSizeLen);

    // free whatever we allocated
    if(hash_hex)
        free(hash_hex);
    if(hash_base64)
        free(hash_base64);
    if(shaValue)
        free(shaValue);

    return preverify_ok;
}



//========================================================================JNI CODE=================================================================================//

jbyteArray as_byte_array(JNIEnv *env, unsigned char* buf, int len) {
    jbyteArray array = env->NewByteArray (len);
    env->SetByteArrayRegion (array, 0, len, reinterpret_cast<jbyte*>(buf));
    return array;
}


unsigned char* as_unsigned_char_array(JNIEnv *env, jbyteArray array) {
    int len = env->GetArrayLength (array);
    unsigned char* buf = new unsigned char[len];
    env->GetByteArrayRegion (array, 0, len, reinterpret_cast<jbyte*>(buf));
    return buf;
}


extern "C"
JNIEXPORT jint JNICALL
Java_com_wifiphase2_openssltest_MainActivity_parseAndVerifyOpenSSLCertificate(JNIEnv *env, jobject thiz,
                                                                     /*jobject _assetManager,*/

                                                                     jbyteArray rawCert,
                                                                     jint granularity,
                                                                     jint hash_choice,
                                                                     jstring hash_list,
                                                                     jintArray cum_hash_size,
                                                                     jint cum_hash_size_len) {

    if(DEBUG)
        LOGI("%s\n", OPENSSL_VERSION_TEXT);

    unsigned char *native_raw_cert = as_unsigned_char_array(env, rawCert);
    int native_raw_cert_length = env->GetArrayLength(rawCert);
    int native_granularity = (int)granularity;
    int native_hash_choice = (int)hash_choice;
    const char *native_hash_list = env->GetStringUTFChars(hash_list, nullptr);
    jint* native_cum_hash_size = env->GetIntArrayElements(cum_hash_size, nullptr);
    unsigned int native_cum_hash_size_len = (unsigned int)cum_hash_size_len;

    if(DEBUG)
        LOGI("from directory: %d\n", native_raw_cert_length);
    if(DEBUG)
        LOGI("from directory: %s\n", native_raw_cert);


    // READ CERTIFICATE AND CREATE X509 OBJECT
    BIO* certBio = BIO_new(BIO_s_mem());
    BIO_write(certBio, native_raw_cert, native_raw_cert_length);
    X509* certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
    if (!certX509) {
        LOGE("Unable to parse certificate in memory\n");
        return -1;
    }

    // USE THE X509 OBJECT HERE

    int verify_status = tls_verify_cb(certX509, native_granularity, native_hash_choice, native_hash_list, native_cum_hash_size, native_cum_hash_size_len);
    /*
     * verify_status values: (different from main android code for testing purposes)
     *  0  => 0 0  => fingerprint mismatch, certificate invalid
     *  1  => 0 1  => fingerprint mismatch, certificate valid (or don't care)
     *  2  => 1 0  => fingerprint match, certificate invalid
     *  3  => 1 1  => fingerprint match, certificate valid (or don't care)
     * */

    if(DEBUG)
        LOGI("Verify Status: %d\n", verify_status);

    // FREE THE X509 OBJECT HERE
    BIO_free(certBio);
    X509_free(certX509);


    env->ReleaseIntArrayElements(cum_hash_size, native_cum_hash_size, 0);
    env->ReleaseStringUTFChars(hash_list, native_hash_list);
    env->ReleaseByteArrayElements(rawCert, reinterpret_cast<jbyte *>(native_raw_cert), 0);
//    delete native_raw_cert;

    return verify_status;

}

/*
    AAssetManager* mgr = AAssetManager_fromJava(env, _assetManager);
    AAsset* asset = AAssetManager_open(mgr, "leaf_certificates/CAT_7.eap-config.pem", AASSET_MODE_UNKNOWN);
    if (NULL == asset) {
        LOGD("FILE NOT FOUND");
        return env->NewStringUTF(h.c_str());
    }
    long size = AAsset_getLength(asset);
    char* buffer = (char*) malloc (sizeof(char)*size);
    AAsset_read (asset,buffer,size);

    LOGD("from asset: %d\n", size);
    LOGD("from asset: %s", buffer);*/



/*    for(int i=0 ; i<size; i++){
        if(i<native_raw_cert_length){
            if(native_raw_cert[i] != buffer[i])
                LOGI("Different at %d", i);
        }
    }*/

