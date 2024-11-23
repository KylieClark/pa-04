/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By: 
     1- Kylie Clark 
	 2- Cole Strubhar   (or risk losing points )
Submitted on: 
     Insert the date of Submission here
	 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//
//  ALL YOUR  CODE FORM  PREVIOUS PAs  and pLABs

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "\n%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}


//-----------------------------------------------------------------------
// Encrypt the plain text stored at 'pPlainText' into the
// caller-allocated memory at 'pCipherText'
// caller must allocate sufficient memory for the cipher text
// returns size of the cipher text in bytes

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len,
		const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText)
{
   int      status ;
   unsigned len=0 , encryptedLen=0 ;

   /* Create and initialise the context */
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   if( ! ctx)
   {
      handleErrors("encrypt: failed to create CTX");
   }

   // Initialise the encryption operation.
   status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv );
   if( status != 1)
      handleErrors("encrypt: failed to EncryptInit_ex");

   // Call EncryptUpdate as many times as needed (e.g. inside a loop)
   // to perform regular encryption
   status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
   if( status != 1){
      handleErrors("encrypt: failed to EncryptUpdate");
   }
   encryptedLen += len;

   // If additonal ciphertext may still be generated,
   // the pCipherText pointer first be advanced forward
   pCipherText += len;

   // Finalize the encryption
   status = EVP_EncryptFinal_ex( ctx, pCipherText, &len);
   if( status != 1){
      handleErrors("encrypt: failed to EncryptFinal_ex");
   }
   encryptedLen += len; // len could be 0 if no addiotnal cipher text was generated

   /* Clean up */
   EVP_CIPHER_CTX_free(ctx);


   return encryptedLen;
}

//--------------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the
// caller allocated memory at 'pDecryptedText'
// caller must allocate sufficent memory for the decrypted text
// returns size of the decrypted text in bytes

unsigned decrypt (uint8_t *pCipherText, unsigned cipherText_len,
	 	const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
   int status ;
   unsigned len=0 , decryptedLen=0;
   /* Create and initialise the context */
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   if ( !ctx){
      handleErrors("decrypt: failed to create CTX");
   }

   // Initialise the decryption operation.
   status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv);
   if (status != 1){
      handleErrors("decrypt: failed to DecryptInit_ex");
   }

   // Call DecryptUpdate as many times as needed (e.g. inside a loop)
   // to perform regular decryption
   status = EVP_DecryptUpdate( ctx, pDecryptedText, &len, pCipherText, cipherText_len);
   if( status != 1){
      handleErrors("decrypt: failed to DecryptUpdate");
   }
   decryptedLen += len;

   // If additional decrypted text may still be generated,
   // the pDecryptedText pointer must be first advanced forward
   pDecryptedText += len;

   // Finalize the decryption.
   status = EVP_DecryptFinal_ex ( ctx, pDecryptedText , &len);
   if (status != 1){
      handleErrors("decrypt: failed to DecryptFinal_ex");
   }
   decryptedLen += len;

   /* Clean up */
   EVP_CIPHER_CTX_free(ctx);

   return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************


static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , 
                       ciphertext[ CIPHER_LEN_MAX    ] ,
                       decryptext[ DECRYPTED_LEN_MAX ] ;

int encryptFile ( int fd_in , int fd_out , const uint8_t *key, const uint8_t *iv)
{
   int status;
   unsigned len = 0;
   unsigned encryptedLen = 0;

   /* create context */
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   if (!ctx)
      {handleErrors("encrypt: failed to create ctx");}

   /* initialize encrypt */
   status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
   if (status != 1)
      {handleErrors("encrypt: failed init");}

   /* LOOP CONDITIONS and encryption */
   size_t bytes_read;
   size_t bytes_written;

   while(1)
   {
      bytes_read = read(fd_in, plaintext, PLAINTEXT_LEN_MAX);
      if (bytes_read == -1)
         {handleErrors("encrypt: error reading bytes");}
      if(bytes_read == 0) break;
      
      status = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, bytes_read);
      if (status != 1)
         {handleErrors("encrypt: failed update");}

      /* WRITE ENCRYPTED digestFER TO PIPE */
      bytes_written = write(fd_out, ciphertext, len);
      if (bytes_written == -1){
         handleErrors("encrypt: failed write");
      }
      encryptedLen += len;
   }

   /* finalize, gets input location from ctx, no arg */
   status = EVP_EncryptFinal_ex(ctx, ciphertext, &len);
   if (status != 1)
      {handleErrors("encrypt: failed to finalize");}
   encryptedLen += len;

   /* WRITE ENCRYPTED digestFER TO PIPE */
   bytes_written = write(fd_out, ciphertext, len);
   if(bytes_written == -1 ){
      handleErrors("encrypt: failed write");
   }

   /* CLEANUP */
   EVP_CIPHER_CTX_free(ctx);

   /* return */
   return encryptedLen;
}

int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
   int status;
   unsigned len = 0;
   unsigned decryptLen = 0;

   /* create context */
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   if ( !ctx){
      handleErrors("decrypt: failed to create CTX");
   }

   /* initialize encrypt */
   status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv);
   if (status != 1){
      handleErrors("decrypt: failed to DecryptInit_ex");
   }

   /* LOOP CONDITIONS and encryption */
   size_t bytes_read;
   size_t bytes_written;

   while(1)
   {
      bytes_read = read(fd_in, ciphertext, CIPHER_LEN_MAX);
      if (bytes_read == -1)
         {handleErrors("decrypt: error reading bytes");}
      if(bytes_read == 0) break;
      
      status = EVP_DecryptUpdate(ctx, decryptext, &len, ciphertext, bytes_read);
      if (status != 1)
         {handleErrors("decrypt: failed update");}

      /* WRITE DECRYPTED digestFER TO PIPE */
      bytes_written = write(fd_out, decryptext, len);
      if (bytes_written == -1){
         handleErrors("decrypt: failed write");
      }
      decryptLen += len;
   }

   /* finalize, gets input location from ctx, no arg */
   status = EVP_DecryptFinal_ex ( ctx, decryptext , &len);
   if (status != 1){
      handleErrors("decrypt: failed to DecryptFinal_ex");
   }
   decryptLen += len;

   /* WRITE DECRYPTED digestFER TO PIPE */
   bytes_written = write(fd_out, decryptext, len);
   if(bytes_written == -1 ){
      handleErrors("encrypt: failed write");
   }

   /* CLEANUP */
   EVP_CIPHER_CTX_free(ctx);

   /* return */
   return decryptLen;
}

//***********************************************************************
// pLAB-02
//***********************************************************************


EVP_PKEY *getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");
    if (fp == NULL)
    {
        fprintf( stderr , "getRSAfromFile: Unable to open RSA key file %s \n",filename);
        return NULL;    
    }

    EVP_PKEY *key = EVP_PKEY_new() ;
    if ( public )
        key = PEM_read_PUBKEY( fp, &key , NULL , NULL );
    else
        key = PEM_read_PrivateKey( fp , &key , NULL , NULL );
 
    fclose( fp );

    return key;
}



//***********************************************************************
// PA-02
//***********************************************************************
// Sign the 'inData' array into the 'sig' array using the private 'privKey'
// 'inLen' is the size of the input array in bytes.
// the '*sig' pointer will be allocated memory large enough to store the signature
// report the actual length in bytes of the result in 'sigLen' 
//
// Returns: 
//    1 on success, or 0 on ANY REASON OF FAILURE

int privKeySign( uint8_t **sig , size_t *sigLen , EVP_PKEY  *privKey , 
                 uint8_t *inData , size_t inLen ) 
{
    // Guard against incoming NULL pointers
    if(!sig || !sigLen || !privKey || !inData || !inLen)
    {
        return 0;
    }

    // Create and Initialize a context for RSA private-key signing
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privKey, NULL);
    if (!ctx)
    {      
        EVP_PKEY_CTX_free(ctx);
        printf("privKeySign: failed to create");
        return 0;
    }
    if (EVP_PKEY_sign_init(ctx) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        printf("privKeySign: failed to init");
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        printf("privKeySign: failed to padding");
        return 0;
    }

    // Determine how big the size of the signature could be
    size_t cipherLen ; 
    if(EVP_PKEY_sign(ctx, NULL, &cipherLen, inData, inLen) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      free(*sig);
      printf("privKeySign: failed to sign1");
      return 0;
    }
    // Next allocate memory for the ciphertext
    *sig = malloc(cipherLen);

    // Now, actually sign the inData using EVP_PKEY_sign( )
    if(EVP_PKEY_sign(ctx, *sig, &cipherLen, inData, inLen) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      free(*sig);
      printf("privKeySign: failed to sign2");
      return 0;
    }

    *sigLen = cipherLen;

    // All is good
    EVP_PKEY_CTX_free( ctx );     // remember to do this if any failure is encountered above

    return 1;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey' 
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int pubKeyVerify( uint8_t *sig , size_t sigLen , EVP_PKEY  *pubKey 
           , uint8_t *data , size_t dataLen ) 
{
    // Guard against incoming NULL pointers
    if ( !sig ||  !pubKey  ||  !data  )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    // Create and Initialize a context for RSA public-key signature verification
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
    if(!ctx)
    {
      EVP_PKEY_CTX_free(ctx);
      printf("pubKeyVerify: failed to create");
      return 0;
    }
    if(EVP_PKEY_verify_init(ctx) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      printf("pubKeyVerify: failed to init");
      return 0;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      printf("pubKeyVerify: failed to pad");
      return 0;
    }

    // Verify the signature vs the incoming data using this context
    int decision = EVP_PKEY_verify(ctx, sig, sigLen, data, dataLen);
    if(decision <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      printf("pubKeyVerify: failed to verify");
      return 0;
    }

    //  free any dynamically-allocated objects 
    EVP_PKEY_CTX_free(ctx);

    return decision ;

}

//-----------------------------------------------------------------------------


size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, also write a copy of the incoming data stream file to 'fd_out'
// Returns actual size in bytes of the computed digest
{
    EVP_MD_CTX *mdCtx ;
    size_t nBytes ;
    unsigned int  mdLen ;

	// Use EVP_MD_CTX_create() to create new hashing context 
   mdCtx = EVP_MD_CTX_create(); 
   if(!mdCtx)
   {
      EVP_MD_CTX_free(mdCtx);
      handleErrors("fileDigest: mdCtx failed to create");

   }  
    // EVP_MD_CTX_new()
    
    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the HASH_ALGORITHM() hashing function 
    EVP_DigestInit(mdCtx, HASH_ALGORITHM());

    while ( 1 )   // Loop until end-of input file
    {
        // Read a chund of input from fd_in. Exit the loop when End-of-File is reached
        nBytes = read(fd_in, digest, EVP_MAX_MD_SIZE);
        if(nBytes == -1) handleErrors("fileDigest: failed to read");

        if(nBytes == 0) break;

        if(EVP_DigestUpdate(mdCtx, digest, nBytes) <= 0) handleErrors("fileDigest: failed update");
        
        // if ( fd_out > 0 ) send the above chunk of data to fd_out
        if(fd_out > 0)
        {
            write(fd_out, digest, nBytes);
        }
            
    }

    if(EVP_DigestFinal(mdCtx, digest, &mdLen) <= 0) handleErrors("fileDigest: failed final");
    
    EVP_MD_CTX_destroy(mdCtx);

    return mdLen ;
}

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are size_t integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

size_t MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments
    if (log == NULL || msg1 == NULL || *msg1 == NULL || IDa == NULL || IDb == NULL) {
        printf("Null pointer detected!\n");
        exit(-1);
    }


    size_t  LenA    = strlen(IDa) + 1; //  number of bytes in IDa (added one to account for '\0');
    size_t  LenB    = strlen(IDb) + 1; //  number of bytes in IDb (added one to account for '\0');
    size_t  LenMsg1 =  sizeof(LenA) + LenA + sizeof(LenB) + LenB + sizeof(Nonce_t); //  number of bytes in the completed MSG1 ;;
    size_t *lenPtr ; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    *msg1 = malloc(LenMsg1);

    if (*msg1 == NULL) {
        printf("myCrypto.c, msg1 failed to malloc!\n");
        exit(-1);
    }
    

    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;
    memset(p, 0, LenMsg1);
    
	// use the pointer p to traverse through msg1 and fill the successive parts of the msg 

    *((unsigned long *) p) = LenA;
    p += sizeof(size_t);
    
    strcpy(p, IDa);
    p += LenA;

    *((unsigned long *) p) = LenB;
    p += sizeof(size_t);

    strcpy(p, IDb);
    p += LenB;

    *((uint32_t *) p) = *Na;
    

    fprintf( log , "The following new MSG1 ( %lu bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    // BIO_dumpt the completed MSG1 indented 4 spaces to the right
    BIO_dump_indent_fp(log, *msg1, LenMsg1, 4);

    fprintf( log , "\n" ) ;
    
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments

    if (log == NULL || IDa == NULL || *IDa == NULL || IDb == NULL || *IDb == NULL) {
        printf("myCrypto.c, null pointer detected!\n");
        exit(-1);
    }

    size_t LenMsg1 = 0, LenA , lenB ;
	// Throughout this function, don't forget to update LenMsg1 as you receive its components
 
    // Read in the components of Msg1:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na

    // 1) Read Len(ID_A)  from the pipe ... But on failure to read Len(IDa):

    if (read(fd, &LenA, sizeof(size_t)) < sizeof(size_t)) 
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDA) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenA in MSG1_receive()" );
    }

    LenMsg1 += sizeof(size_t);
    
    // 2) Allocate memory for ID_A ... But on failure to allocate memory:

    if ((*IDa = (char *) (malloc(LenA))) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

 	// On failure to read ID_A from the pipe
    if (read(fd, *IDa, LenA) < LenA)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }
    LenMsg1 += LenA;

    // 3) Read Len( ID_B )  from the pipe    But on failure to read Len( ID_B ):
    if (read(fd, &lenB, sizeof(size_t)) < sizeof(size_t))
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDB) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of LenB in MSG1_receive()" );
    }
    LenMsg1 += sizeof(size_t);

    // 4) Allocate memory for ID_B    But on failure to allocate memory:
    if ((*IDb = (char *) malloc(lenB)) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG1_receive()" );
    }

 	// Now, read IDb ... But on failure to read ID_B from the pipe
    if (read(fd, *IDb, lenB) < lenB)
    {
        fprintf( log , "Unable to receive all %lu bytes of IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDB in MSG1_receive()" );
    }
    LenMsg1 += lenB;

    // 5) Read Na   But on failure to read Na from the pipe
    if (read(fd, Na, sizeof(Nonce_t)) < sizeof(Nonce_t))
    {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG1_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG1_receive()" );
    }
    LenMsg1 += sizeof(Nonce_t);
 
    fprintf( log , "MSG1 ( %lu bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}



//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************
//  Use these static arrays from PA-01 earlier

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application



// Also, use this new one for your convenience
static unsigned char   ciphertext2[ CIPHER_LEN_MAX    ] ; // Temporarily store outcome of encryption

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are size_t integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

size_t MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{
    if(log == NULL || msg2 == NULL || Ka == NULL || Kb == NULL || Ks == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
        printf("myCrypto.c, MSG2 null pointer detected!\n");
        exit(-1);
    }

    size_t LenA    = strlen(IDa) + 1; //  number of bytes in IDa (added one to account for '\0')
    size_t LenB    = strlen(IDb) + 1; //  number of bytes in IDb (added one to account for '\0')
    size_t LenMsg2;
    size_t LenMsg2e = 0;
    size_t LenTktPlain = 0;
    size_t LenTktCipher;


    //---------------------------------------------------------------------------------------
    // Construct TktPlain = { Ks  || L(IDa)  || IDa }
    // in the global scratch buffer plaintext[]
    uint8_t *p;
    p = plaintext;
        
    memcpy(p, Ks, KEYSIZE);
    p += KEYSIZE;
    LenTktPlain += KEYSIZE;

    // strcpy(p, LenA);
    // p += sizeof(LenA);

    *((unsigned long *) p) = LenA;
    p += sizeof(size_t);
    LenTktPlain += sizeof(size_t);
    
    memcpy(p, IDa, LenA);
    p += LenA;
    LenTktPlain += LenA;

    // Use that global array as a scratch buffer for building the plaintext of the ticket
    // Compute its encrypted version in the global scratch buffer ciphertext[]

    // Now, set TktCipher = encrypt( Kb , plaintext );
    // Store the result in the global scratch buffer ciphertext[]
    size_t TktCipher = encrypt(plaintext, PLAINTEXT_LEN_MAX, Kb->key, Kb->iv, ciphertext);

    //---------------------------------------------------------------------------------------
    // Construct the rest of Message 2 then encrypt it using Ka
    // MSG2 plain = {  Ks || L(IDb) || IDb  ||  Na || L(TktCipher) || TktCipher }

    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || L(Na) || Na || lenTktCipher) || TktCipher
    // Reuse that global array plaintext[] as a scratch buffer for building the plaintext of the MSG2

    p = plaintext;
    
    memcpy(p, Ks, KEYSIZE);
    p += KEYSIZE;
    LenMsg2e += KEYSIZE;

    *((unsigned long *) p) = LenB;
    p += sizeof(size_t);
    LenMsg2e += sizeof(size_t);

    memcpy(p, IDb, LenB);
    p += LenB;
    LenMsg2e += LenB;

    *((uint32_t *) p) = **Na;
    p += NONCELEN;

    memcpy(p, Na, NONCELEN);
    p += NONCELEN;

    *((uint32_t *) p) = LenTktCipher;
    p += sizeof(LenTktCipher);
    LenMsg2e += sizeof(LenTktCipher);

    memcpy(p, ciphertext, LenTktCipher);
    p += LenTktCipher;
    LenMsg2e += LenTktCipher;

    // Now, encrypt Message 2 using Ka. 
    // Use the global scratch buffer ciphertext2[] to collect the results

    LenMsg2 = encrypt(plaintext, LenMsg2e, Ka->key, Ka->iv, ciphertext2);

    // allocate memory on behalf of the caller for a copy of MSG2 ciphertext
    *msg2 = malloc(LenMsg2);
    if (*msg2 == NULL) {
        printf("myCrypto.c, msg2 failed to malloc!\n");
        exit(-1);
    }

    // Copy the encrypted ciphertext to Caller's msg2 buffer.
    memcpy(*msg2, ciphertext2, LenMsg2);

    fprintf( log , "\nThe following Encrypted MSG2 ( %lu bytes ) has been"
                   " created by MSG2_new():  \n" ,  LenMsg2  ) ;
    BIO_dump_indent_fp( log , msg2 ,  LenMsg2  , 4 ) ;    fprintf( log , "\n" ) ;    

    fprintf( log ,"\nThis is the content of MSG2 ( %lu Bytes ) before Encryption:\n" ,  LenMsg2e );  
    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , KEYSIZE );
    BIO_dump_indent_fp ( log ,  Ks  ,  KEYSIZE  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"\n    IDb (%lu Bytes) is:\n" , LenB);
    BIO_dump_indent_fp ( log ,  IDb  ,  LenB  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"\n    Na (%lu Bytes) is:\n" , NONCELEN);
    BIO_dump_indent_fp ( log ,  Na  ,  NONCELEN  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"\n    Encrypted Ticket (%lu Bytes) is\n" ,  LenMsg2 );
    BIO_dump_indent_fp ( log ,  ciphertext  ,  LenTktCipher  , 4 ) ;  fprintf( log , "\n") ; 

    // fflush( log ) ;    
    
    return LenMsg2 ;    

}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , size_t *lenTktCipher , uint8_t **tktCipher )
{
// Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher

    if (!log || fd < 0 || !Ka || !Ks || !IDb || !Na || !lenTktCipher || !tktCipher) {
        exitError("Received null pointers or invalid file descriptor in MSG2_receive\n");
    }
	
	size_t LenMsg2 = 0, readML, LenB, tktPlain;
    uint8_t *p;
    uint8_t *msg2;

	// Read length of msg2 first
    if (read(fd, &readML, sizeof(size_t)) < sizeof(size_t))
    {
        fprintf( log , "Unable to receive all %lu bytes of readML(msg2) "
                       "in MSG2_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of ml2 in MSG2_receive()" );
    }
    // LenMsg2 += sizeof(size_t);

    LenMsg2 = read(fd, ciphertext, sizeof(ciphertext));
    if (LenMsg2 != readML) {
        exitError("Failed to read MSG2 from file descriptor\n");
    }

    fprintf( log ,"MSG2_receive() got the following Encrypted MSG2 ( %lu bytes ) Successfully\n" 
                 , LenMsg2 );
	BIO_dump_indent_fp(log, (const char *) ciphertext, LenMsg2, 4);
    fprintf(log, "\n");
	
	fflush(log);
	
	tktPlain = decrypt(ciphertext, LenMsg2, Ka->key, Ka->iv, decryptext);
    if (readML <= 0) {
        exitError("Failed to decrypt MSG2\n");
    }
	
    p = decryptext;

    memcpy(Ks, p, KEYSIZE);
    p += KEYSIZE;
	
    memcpy(&LenB, p, LENSIZE);
    p += LENSIZE;

    if ((*IDb = (char *) malloc(LenB)) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDB in MSG2_receive() "
                       "... EXITING\n" , LenB);
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG2_receive()" );
    }
    memcpy(*IDb, p, LenB);
    p += LenB;

    memcpy(*Na, p, NONCELEN);
    p += NONCELEN;

    memcpy(lenTktCipher, p, sizeof(size_t));
    p += sizeof(size_t);

    if ((*tktCipher = (uint8_t *) malloc(*lenTktCipher)) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for tktCipher in MSG2_receive() "
                       "... EXITING\n" , LenB);
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating tktCipher in MSG2_receive()" );
    }
    memcpy(*tktCipher, p, *lenTktCipher);


    fprintf( log ,"MSG2_receive() got the following Encrypted MSG2 ( %lu bytes ) Successfully\n" 
                 , LenMsg2 );
    BIO_dump_indent_fp( log, ciphertext, LenMsg2, 4);
    fprintf ( log, "\n");

        // // 2) Allocate memory for msg2
    // if ((msg2 = (uint8_t *)malloc(readML)) == NULL)
    // {
    //     fprintf( log , "Out of Memory allocating %lu bytes for msg2 in MSG2_receive() "
    //                    "... EXITING\n" , lenTktCipher );
    //     fflush( log ) ;  fclose( log ) ;
    //     exitError( "Out of Memory allocating ml2 in MSG2_receive()" );
    // }

 	// // 3) Read LenB from the pipe
    // if (read(fd, LenB, sizeof(size_t)) < sizeof(size_t))
    // {
    //     fprintf( log , "Unable to receive all %lu bytes of LenB in MSG2_receive() "
    //                    "... EXITING\n" , lenTktCipher );
    //     fflush( log ) ;  fclose( log ) ;
    //     exitError( "Unable to receive all bytes of LenB in MSG2_receive()" );
    // }
    // LenMsg2 += sizeof(size_t);

    // // 4) Allocate memory for LenB
    // if ((msg2 = (uint8_t *)malloc(readML)) == NULL)
    // {
    //     fprintf( log , "Out of Memory allocating %lu bytes for msg2 in MSG2_receive() "
    //                    "... EXITING\n" , lenTktCipher );
    //     fflush( log ) ;  fclose( log ) ;
    //     exitError( "Out of Memory allocating ml2 in MSG2_receive()" );
    // }

 	// // 5) Read IDb from the pipe
    // if (read(fd, IDb, LenB) < LenB)
    // {
    //     fprintf( log , "Unable to receive all %lu bytes of LenB in MSG2_receive() "
    //                    "... EXITING\n" , lenTktCipher );
    //     fflush( log ) ;  fclose( log ) ;
    //     exitError( "Unable to receive all bytes of LenB in MSG2_receive()" );
    // }
    // LenMsg2 += LenB;

    // // 6) Read Na2 from the pipe
    // if (read(fd, Na, sizeof(Nonce_t)) < sizeof(Nonce_t))
    // {
    //     fprintf( log , "Unable to receive all %lu bytes of Na "
    //                    "in MSG2_receive() ... EXITING\n" , NONCELEN );
        
    //     fflush( log ) ;  fclose( log ) ;   
    //     exitError( "Unable to receive all bytes of Na in MSG2_receive()" );
    // }
    // LenMsg2 += sizeof(Nonce_t);

    // // 7) Read lenTktCipher from the pipe
    // if (read(fd, &lenTktCipher, sizeof(size_t)) < sizeof(size_t))
    // {
    //     fprintf( log , "Unable to receive all %lu bytes of lenTktCipher(tktCipher) "
    //                    "in MSG2_receive() ... EXITING\n" , LENSIZE );
        
    //     fflush( log ) ;  fclose( log ) ;   
    //     exitError( "Unable to receive all bytes of lenTktCipher in MSG2_receive()" );
    // }
    // LenMsg2 += sizeof(size_t);

    // // 8) Allocate memory for TktCipher
    // if ((tktCipher = (uint8_t *)malloc(lenTktCipher)) == NULL)
    // {
    //     fprintf( log , "Out of Memory allocating %lu bytes for tktCipher in MSG2_receive() "
    //                    "... EXITING\n" , lenTktCipher );
    //     fflush( log ) ;  fclose( log ) ;
    //     exitError( "Out of Memory allocating tktCipher in MSG2_receive()" );
    // }

 	// // 9) Read TktCipher from the pipe
    // if (read(fd, tktCipher, lenTktCipher) < lenTktCipher)
    // {
    //     fprintf( log , "Unable to receive all %lu bytes of tktCipher in MSG2_receive() "
    //                    "... EXITING\n" , lenTktCipher );
    //     fflush( log ) ;  fclose( log ) ;
    //     exitError( "Unable to receive all bytes of tktCipher in MSG2_receive()" );
    // }
    // LenMsg2 += *lenTktCipher;

}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

size_t MSG3_new( FILE *log , uint8_t **msg3 , const size_t lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{


    //  Check agains any NULL pointers in the arguments
    if (log == NULL || msg3 == NULL || !lenTktCipher || tktCipher == NULL || Na2 == NULL) {
        printf("Null pointer detected!\n");
        exit(-1);
    }

    size_t LenMsg3 = sizeof(lenTktCipher) + lenTktCipher + sizeof(Nonce_t);
    size_t *lenPtr ; 
    uint8_t *p ;

    *msg3 = malloc(LenMsg3);

    if (*msg3 == NULL) {
        printf("myCrypto.c, msg3 failed to malloc!\n");
        exit(-1);
    }
    

    // Fill in MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
    p = *msg3;
    memset(p, 0, LenMsg3);
    
	// use the pointer p to traverse through msg3 and fill the successive parts of the msg 

    *((unsigned long *) p) = lenTktCipher;
    p += sizeof(size_t);
    
    memcpy(p, tktCipher, lenTktCipher);
    p += lenTktCipher;

    *((uint32_t *) p) = **Na2;

    

    fprintf( log , "The following MSG3 ( %lu bytes ) has been created by "
                   "MSG3_new ():\n" , LenMsg3 ) ;
    BIO_dump_indent_fp( log , *msg3 , LenMsg3 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return( LenMsg3 ) ;

}

// //-----------------------------------------------------------------------------
// // Receive Message #3 by Basim from Amal
// // Parse the incoming msg3 into its components Ks , IDa , and Na2
// // The buffers for Kb, Ks, and Na2 are pre-created by the caller
// // The value of Kb is set by the caller
// // The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{
// L(TktCipher)  || TktCipher  ||  Na2

    size_t LenMsg3;
    size_t lenTktCipher, lenTktPlain, LenA;
    uint8_t *tktCipher;
    uint8_t *p;


    // 1) Read lenTktCipher from the pipe
    if (read(fd, &lenTktCipher, sizeof(size_t)) < sizeof(size_t))
    {
        fprintf( log , "Unable to receive all %lu bytes of lenTktCipher(tktCipher) "
                       "in MSG3_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of lenTktCipher in MSG3_receive()" );
    }
    LenMsg3 += sizeof(size_t);

    // 2) Allocate memory for TktCipher
    if ((tktCipher = (uint8_t *)malloc(lenTktCipher)) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for tktCipher in MSG3_receive() "
                       "... EXITING\n" , lenTktCipher );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating tktCipher in MSG3_receive()" );
    }

 	// 3) Read TktCipher from the pipe
    if (read(fd, tktCipher, lenTktCipher) < lenTktCipher)
    {
        fprintf( log , "Unable to receive all %lu bytes of tktCipher in MSG3_receive() "
                       "... EXITING\n" , lenTktCipher );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of tktCipher in MSG3_receive()" );
    }
    LenMsg3 += lenTktCipher;

    // 4) Read Na2 from the pipe
    if (read(fd, Na2, sizeof(Nonce_t)) < sizeof(Nonce_t))
    {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG2_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG3_receive()" );
    }
    LenMsg3 += sizeof(Nonce_t);

    memcpy(ciphertext, tktCipher, lenTktCipher);

    lenTktPlain = decrypt(ciphertext, lenTktCipher, Kb->key, Kb->iv, decryptext);

    p = decryptext;

    memcpy(Ks, p, KEYSIZE);
    p += KEYSIZE;
	
    memcpy(&LenA, p, LENSIZE);
    p += LENSIZE;

    if ((*IDa = (char *) malloc(LenA)) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG2_receive() "
                       "... EXITING\n" , LenA);
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG2_receive()" );
    }
    memcpy(*IDa, p, LenA);


    fprintf( log ,"The following Encrypted TktCipher ( %lu bytes ) was received by MSG3_receive()\n" 
                 , lenTktCipher  );
    BIO_dump_indent_fp( log , ciphertext , lenTktCipher , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;



    fprintf( log ,"Here is the Decrypted Ticket ( %lu bytes ) in MSG3_receive():\n" , lenTktPlain ) ;
    BIO_dump_indent_fp( log , decryptext , lenTktPlain , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;



}

// //-----------------------------------------------------------------------------
// // Build a new Message #4 from Basim to Amal
// // MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// // A new buffer for *msg4 is allocated here
// // All other arguments have been initialized by caller

// // Returns the size of Message #4 after being encrypted by Ks in bytes

size_t  MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{

    size_t LenMsg4 ;

    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values


    // Now, encrypt MSG4 plaintext using the session key Ks;
    // Use the global scratch buffer ciphertext[] to collect the result. Make sure it fits.

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    // *msg4 = malloc( .... ) ;



    
    fprintf( log , "The following Encrypted MSG4 ( %lu bytes ) has been"
                   " created by MSG4_new ():  \n" , LenMsg4 ) ;
    // BIO_dump_indent_fp( log , *msg4 , ... ) ;

    return LenMsg4 ;
    

}

// //-----------------------------------------------------------------------------
// // Receive Message #4 by Amal from Basim
// // Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{


}

// //-----------------------------------------------------------------------------
// // Build a new Message #5 from Amal to Basim
// // A new buffer for *msg5 is allocated here
// // MSG5 = Encr( Ks  ,  { fNb }  )
// // All other arguments have been initialized by caller
// // Returns the size of Message #5  in bytes

size_t  MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{
    size_t  LenMSG5cipher  ;

    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits 


    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.


    // Now allocate a buffer for the caller, and copy the encrypted MSG5 to it
    // *msg5 = malloc( ... ) ;


    fprintf( log , "The following Encrypted MSG5 ( %lu bytes ) has been"
                   " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    BIO_dump_indent_fp( log , *msg5 , LenMSG5cipher , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return LenMSG5cipher ;

}

// //-----------------------------------------------------------------------------
// // Receive Message 5 by Basim from Amal
// // Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{

    size_t    LenMSG5cipher ;
    
    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.


    fprintf( log ,"The following Encrypted MSG5 ( %lu bytes ) has been received:\n" , LenMSG5cipher );


    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits


    // Parse MSG5 into its components f( Nb )



}

// //-----------------------------------------------------------------------------
// // Utility to compute r = F( n ) for Nonce_t objects
// // For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// // where b = number of bits in a Nonce_t object
// // The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    // Note that the nonces are store in Big-Endian byte order
    // This affects how you do arithmetice on the noces, e.g. when you add 1
}
