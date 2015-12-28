#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/mm.h> // for verify_area: defined in uacces.h
#include <linux/highmem.h>
#include <linux/slab.h>// for kmalloc and kfree
#include <linux/fs.h> // for file api
#include <linux/types.h>// for u8
#include <linux/stat.h> // for checking dir or file
# include <linux/namei.h>
// for crypto stuff
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/md5.h>
#include <crypto/hash.h>

#include "sys_xcrypt.h"

// courtesy: fs/ecryptfs/crypto.c
#define DECRYPT 0
#define ENCRYPT 1

#define MD5_DIGEST_LENGTH 16 

struct xcryptargs* kCryptArgs;

/*
 * This method is a courtesy of net/ceph/crypto.c
 * Thanks to: http://stackoverflow.com/questions/6059528
 * /want-an-example-for-using-aes-encryption-method-in-kernel-version-above-or-equal
 * It initializes the encryption/decryption destination buffer
 */
int setup_sgtable(struct sg_table *sgt, struct scatterlist *prealloc_sg,
                         const void *buf, unsigned int buf_len)
 {
     struct scatterlist *sg;
     const bool is_vmalloc = is_vmalloc_addr(buf);
     unsigned int off = offset_in_page(buf);
     unsigned int chunk_cnt = 1;
     unsigned int chunk_len = PAGE_ALIGN(off + buf_len);
     int i;
     int ret;
 
     if (buf_len == 0)
    {
         memset(sgt, 0, sizeof(*sgt));
         return -EINVAL;
    }
 
    if (is_vmalloc)
    {
         chunk_cnt = chunk_len >> PAGE_SHIFT;
         chunk_len = PAGE_SIZE;
    }
 
    if (chunk_cnt > 1)
    {
        ret = sg_alloc_table(sgt, chunk_cnt, GFP_NOFS);
        if (ret)
            return ret;
    } else
    {
        WARN_ON(chunk_cnt != 1);
        sg_init_table(prealloc_sg, 1);
        sgt->sgl = prealloc_sg;
        sgt->nents = sgt->orig_nents = 1;
    }
 
    for_each_sg(sgt->sgl, sg, sgt->orig_nents, i)
    {
        struct page *page;
        unsigned int len = min(chunk_len - off, buf_len);
 
        if (is_vmalloc)
            page = vmalloc_to_page(buf);
        else
            page = virt_to_page(buf);
 
        sg_set_page(sg, page, len, off);
 
        off = 0;
        buf += len;
        buf_len -= len;
     }
     WARN_ON(buf_len != 0);
 
     return 0;
 }

/*
 * Frees the sg_table initialized in setup sg_table
 * This method is a courtesy of net/ceph/crypto.c
 */
void teardown_sgtable(struct sg_table *sgt)
 {
    if (sgt->orig_nents > 1)
        sg_free_table(sgt);
 }

/*
 * This method is a courtesy of net/ceph/crypto.c
 * it places the encrypted buffer in dst by encrypting the src using key
 * This method employs a beautiful way of padding, which avoids to store pad byte in the header
 */

int ceph_aes_encrypt(const void *key, int key_len, void *dst, size_t *dst_len,
                      const void *src, size_t src_len, char* aes_iv){
    
    struct scatterlist sg_in[2], prealloc_sg;
    struct sg_table sg_out;    
    // allocate the cipher handle for the AES block cipher
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
    struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
    int ret;
    void *iv;
    int ivsize;
    // zero_padding holds the number by which it falls short by 16
    // the last 4 bits of the src length is taken and subtracted from 16
    // this gives the length to be padded.
    // if the src_len is a multiple of 16, we dont hold 0, but instead we hold 16
    size_t zero_padding = (0x10 - (src_len & 0x0f));
    char pad[16];
    
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    
    // Below is a brilliant step ( by ceph/crypto.c) of padding the src with the amount to be padded
    // This way after decryption, when we check the last byte, we know how much padding was added
    // and subtract it from dest length 
    memset(pad, zero_padding, zero_padding);
    
    //  update the destination length to reflect the padding done to source
    *dst_len = src_len + zero_padding;

    sg_init_table(sg_in, 2);
    sg_set_buf(&sg_in[0], src, src_len);
    sg_set_buf(&sg_in[1], pad, zero_padding);
    ret = setup_sgtable(&sg_out, &prealloc_sg, dst, *dst_len);

    if (ret)
        goto out_tfm;
    
    // set the symmetric key
    crypto_blkcipher_setkey((void *)tfm, key, key_len);
    // get the address to store the instantiation vector
    iv = crypto_blkcipher_crt(tfm)->iv;
    // query the cipher handle for the length of IV
    // we know that atleast it is 16. no need to have special check for aes_iv 
    // as it is always taken care for the length to be atleast 16.
    ivsize = crypto_blkcipher_ivsize(tfm);
    memcpy(iv, aes_iv, ivsize);
 
         
    print_hex_dump(KERN_ERR, "enc key: ", DUMP_PREFIX_NONE, 16, 1,
                        key, key_len, 1);
    print_hex_dump(KERN_ERR, "enc src: ", DUMP_PREFIX_NONE, 16, 1,
                         src, src_len, 1);
    print_hex_dump(KERN_ERR, "enc pad: ", DUMP_PREFIX_NONE, 16, 1,
                         pad, zero_padding, 1);
         
    ret = crypto_blkcipher_encrypt(&desc, sg_out.sgl, sg_in,
                                      src_len + zero_padding);// start encrypting
    if (ret < 0)
    {
        pr_err("ceph_aes_crypt failed %d\n", ret);
        goto out_sg;
    }
         
    print_hex_dump(KERN_ERR, "enc out: ", DUMP_PREFIX_NONE, 16, 1,
                        dst, *dst_len, 1);
         
 
 out_sg:
    teardown_sgtable(&sg_out);
 
 out_tfm:
    crypto_free_blkcipher(tfm);

    return ret;
}


/*
 * This method is a courtesy of net/ceph/crypto.c
 * This method decrypts the given src buf using the key provided and places result into dst
 */
int ceph_aes_decrypt(const void *key, int key_len, void *dst, size_t *dst_len,
                      const void *src, size_t src_len, char* aes_iv){

    struct sg_table sg_in;
    struct scatterlist sg_out[2], prealloc_sg;
    // crypto handle for aes in cipher block chaining mode
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
    struct blkcipher_desc desc = { .tfm = tfm };
    char pad[16];
    void *iv;
    int ivsize;
    int ret;
    int last_byte;
 
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
 
    sg_init_table(sg_out, 2);
    sg_set_buf(&sg_out[0], dst, *dst_len);
    sg_set_buf(&sg_out[1], pad, sizeof(pad));
    ret = setup_sgtable(&sg_in, &prealloc_sg, src, src_len);
    if (ret)
        goto out_tfm;

    print_hex_dump(KERN_ERR, "dec key0: ", DUMP_PREFIX_NONE, 16, 1,
                        key, key_len, 1);
 
    crypto_blkcipher_setkey((void *)tfm, key, key_len);// set decrypt key
    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm);
    memcpy(iv, aes_iv, ivsize);
 
         
    print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, 16, 1,
                        key, key_len, 1);
    print_hex_dump(KERN_ERR, "dec  in: ", DUMP_PREFIX_NONE, 16, 1,
                        src, src_len, 1);
         
    ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in.sgl, src_len);
    if (ret < 0)
    {
        pr_err("ceph_aes_decrypt failed %d\n", ret);
        goto out_sg;
    }
    
    // get the last byte of the decrypted source
    if (src_len <= *dst_len)
        last_byte = ((char *)dst)[src_len - 1];
    else
        last_byte = pad[src_len - *dst_len - 1];

    // this holds by what length you need to go back by rejecting the pad bits
    if (last_byte <= 16 && src_len >= last_byte)
    {
        *dst_len = src_len - last_byte;// source length is now total length - padded bytes
    } else
    {
        pr_err("ceph_aes_decrypt got bad padding %d on src len %d\n",
                        last_byte, (int)src_len);
        return -EPERM;  /* bad padding */
    }
         
    print_hex_dump(KERN_ERR, "dec out: ", DUMP_PREFIX_NONE, 16, 1,
                        dst, *dst_len, 1);
         
 
 out_sg:
    teardown_sgtable(&sg_in);
 out_tfm:
    crypto_free_blkcipher(tfm);

    return ret;
}

/*
 *Checks whether the input file can be opened in read mode
 * if the file is a directory
 * if the file operations on the file allow read
 * courtesy wrapfs_read_file method from hw1.txt
 * fs/open.c
 */
struct file* checkInputFile(char* infile, long* ret)
{
    struct file *filp = NULL;
    
    if(infile == NULL)
    {
       *ret = -EINVAL;
       return filp;
    }

    filp = filp_open(infile, O_RDONLY, 0);

    if (!filp || IS_ERR(filp))
    {
        *ret = -EPERM;
	    printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp));
	    return NULL; 
    }

    // check if opened file is a directory
    if(S_ISDIR(filp->f_path.dentry->d_inode->i_mode))
    {
        *ret = -EISDIR;
        printk("file is a directory\n");
        goto CLOSEFILE;      
    } 
    
    if (!filp->f_op->read)// filesystem doesnot allow reads
    {
        // cannot read, now close file pointer
        *ret = -EPERM;
        goto CLOSEFILE;
    }else
    {
        goto OUT;
    }
    
CLOSEFILE:
    filp_close(filp, NULL);
OUT:
    return filp;
}

/*
 * Check if the file can be opened or created using the permissions of infile
 * Check if the file operations permit write
 * courtesy: fs/open.c
 */
struct file* checkOutputFile(char* outfile,struct file* infile)
{
    struct file *filp = NULL;
 
    if(infile == NULL)
    {
       return filp;
    }
    
    if(outfile == NULL)
    {
       return filp;
    }

    // now get permissions of infile
    umode_t inMode = infile->f_path.dentry->d_inode->i_mode;
    filp = filp_open(outfile, O_WRONLY|O_CREAT, inMode);// automatically follows symlinks

    if (!filp || IS_ERR(filp))
    {
        printk("wrapfs__create_file_ err %d\n", (int) PTR_ERR(filp));
        return NULL;
    }
   
    // check if i can write into this file
    if (!filp->f_op->write)// filesystem doesnot allow writes 
    {
        // cannot write, now close file pointer
        filp_close(filp, NULL);
        return NULL;
    }

    return filp;
}

/*
 * Delete a file , given the file struct
 * Before unlinking close the file
 * Courtesy: fs/namei.c
 */
int deleteFile(struct file* filp)
{
    int ret = 0;
    if( filp == NULL || IS_ERR(filp))
    {
       ret = -EINVAL;
       printk("Passed a empty file pointer. Check Input!\n");
       return ret;
    }

    struct inode* file_inode = filp->f_path.dentry->d_parent->d_inode;
    struct dentry* file_dentry = filp->f_path.dentry;

    if(!filp_close(filp, NULL))
    {
       ret = -EPERM;
       printk("File close failed\n");
       return ret;
    }

    ret = vfs_unlink(file_inode, file_dentry, NULL);
    if(ret != 0)
        printk("Failed to delete the output file");
   else
        printk(" File deletion successfull"); 

    return ret;
}

/*courtesy: fs/ecryptfs/crypto.c: ecryptfs_calculate_md5
 * calculate mds digest of src whose length is len and place in dst
 */
int calculate_md5(char* dst, char* src, int len)
{

    int rc = 0;
    struct hash_desc desc;
    
  
    struct crypto_hash *tfm  = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

    if(!tfm || IS_ERR(tfm))
    {
        rc = PTR_ERR(tfm);
        printk("error allocating crypto context");
        goto OUT;
    }

    desc.tfm = tfm;
    rc = crypto_hash_init(&desc);
    if(rc)
    {
        printk(" error initializing crypto hash");
        goto OUT;
    }

    struct scatterlist sg;
    sg_init_one(&sg, (u8 *)src, len);
    rc = crypto_hash_update(&desc, &sg, len);
    if(rc)
    {
        printk(" error updating  crypto hash");
        goto OUT;
    }


    rc = crypto_hash_final(&desc, dst);
    if(rc)
    {
        printk(" error finalizing crypto hash");
        goto OUT;
    }

OUT:
    return rc;
    
}

/* print bytes in dex value */
void print_md5(unsigned char *mess_dig) {
    int i;
	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        printk("%02x", mess_dig[i]);
	}
	printk("\n");
}

/* 
 * Generate an instantiation vector for every page
 * A predefined string is concatenated with the page number
 * A 16 byte MD5 sum of this string is used as a IV
 */
void getAESinstantiationVector(char* aes, long  pageCount)
{
    #ifdef EXTRA_CREDIT
    char* tempAES = "1234567812345678";// predefined string

    char pageCountBuffer[11]; // max long value is 10 charcters long
    memset(pageCountBuffer, 0, 11);
    sprintf(pageCountBuffer, "%ld", pageCount);

    int totlength = strlen(tempAES) + strlen(pageCountBuffer);
    char* aesbuf = (char*)kmalloc(totlength+1, GFP_KERNEL);
    memset(aesbuf, 0, totlength+1);

    strcat(aesbuf, tempAES); 
    strcat(aesbuf, pageCountBuffer);// concatenate page number

    printk("inst vector: %s, %d\n", aesbuf, strlen(aesbuf));

    calculate_md5(aes, aesbuf, strlen(aesbuf));
    // free aesbuf as we are done with copy
    if(aesbuf)
        kfree(aesbuf);

    #else
    char* tempAES = "1234567812345678";
    memcpy(aes, tempAES, 16);
    #endif
}

/*
 * encrypt the input file using keybuf and place in outputFile
 * msgDigest is the preamble  to be written into the encrypted file 
 */
long doEncrypt(struct file* inputFile, struct file* outputFile, char* msgDigest, int keylen, void* keybuf)
{
    long ret = 0;
    long pageCount = 0;
    printk("Starting to encrypt\n");
    printk("Encrypting with: "); print_md5(keybuf);printk(" whose digest is: "); print_md5(msgDigest);
 
    // set the file positions to the starting
    inputFile->f_pos = 0;
    outputFile->f_pos = 0;

    mm_segment_t oldfs;
    oldfs = get_fs();// store the prev transalation so that we dont mess later
    set_fs(KERNEL_DS);// the read_buffer points to kernel , no need of translation

    // write the message digest to output file
    if(outputFile->f_op->write(outputFile, msgDigest, 16, &(outputFile->f_pos)) == 0) 
    {
        ret = -EIO;
        printk(" Could not write message digest to outfile\n");// delete out file
        goto DELOUTFILE;
    }
 
    // I have a source length, now this can be padded upto a max of 128 bits. srcbuf + pad = page size
    char* read_buffer = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(!read_buffer || IS_ERR(read_buffer))
    {
        ret = -ENOMEM;
        goto DELOUTFILE; // unlink the output file
    }  
    memset(read_buffer, 0, PAGE_SIZE);

    // I have a encryption biffer, which can be equal to the src buffer size
    char* encrypt_buffer = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(!encrypt_buffer || IS_ERR(encrypt_buffer))
    {
        ret = -ENOMEM;
        goto FREEREADBUF; // unlink the output file and free read_buffer
    }
    memset(encrypt_buffer, 0, PAGE_SIZE);

  
    size_t bytesRead = 0;
    size_t writeSize = (size_t) PAGE_SIZE;
  
    while(true)
    {
        memset(read_buffer, 0, PAGE_SIZE);
        memset(encrypt_buffer, 0, PAGE_SIZE);
        // read page size -16 as 16 can be added as padding bytes
        bytesRead = inputFile->f_op->read(inputFile, read_buffer, PAGE_SIZE - 16, &inputFile->f_pos);
        if(bytesRead < 0)
        {
            // if less than 0 free read buffer, write buffer and felete output file
            ret = -EIO;
            goto FREEWRITEBUF;
        }

        if(bytesRead == 0)
        {
            // end of file
            goto FREEWRITEBUF;
        }
        // our encryption destination len would be the bytes read from the file
        printk("Encrypting data which is %d len\n", bytesRead);
        writeSize = bytesRead;
        pageCount++;
        
        char aesIV[17];
        memset(aesIV, 0, 17);
        getAESinstantiationVector(aesIV, pageCount);
        printk("my inst vector: ");print_md5(aesIV);
     
        ret = ceph_aes_encrypt(keybuf, keylen, encrypt_buffer,&writeSize, read_buffer, bytesRead, aesIV);
        printk("Encrypted: %d bytes\n", writeSize);

        if( ret != 0)
        {
            printk("encryption falied");
            //free read buffer, write buffer and felete output file
            goto FREEWRITEBUF;
        }
        // encryption successful, write to output file 
        if(outputFile->f_op->write(outputFile, encrypt_buffer, writeSize, &outputFile->f_pos) <= 0 )
        {
            ret = -EIO;// if writing failed, free read buffer, write buffer and felete output file
            goto FREEWRITEBUF;
        }
    }

FREEWRITEBUF:
    if(encrypt_buffer)
        kfree(encrypt_buffer);
FREEREADBUF:
    if(read_buffer)
        kfree(read_buffer);
DELOUTFILE:
    if( ret != 0)
        deleteFile(outputFile);

    set_fs(oldfs);
    return ret;
}

/*
 * Place the decrypted content into output file 
 * msgDigest should be checked with the preamble
 */
long doDecrypt(struct file* inputFile, struct file* outputFile, char* msgDigest, int keylen, void* keybuf)
{
    long ret = 0;
    long pageCount = 0;
    printk("Starting to decrypt\n");
    printk("Decrypting with the key: "); print_md5(keybuf);

    // set the file positions to the starting
    inputFile->f_pos = 0;
    outputFile->f_pos = 0;

    mm_segment_t oldfs;
    oldfs = get_fs();// store the prev transalation so that we dont mess later
    set_fs(KERNEL_DS);// the read_buffer points to kernel , no need of translation


    char* read_buffer = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(!read_buffer || IS_ERR(read_buffer))
    {
        ret = -ENOMEM;
        goto DELOUTFILE; // unlink the output file
    }
    memset(read_buffer, 0, PAGE_SIZE);

    // I have a decryption buffer, which can be equal to the src buffer size
    char* decrypt_buffer = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(!decrypt_buffer || IS_ERR(decrypt_buffer))
    {
        ret = -ENOMEM;
        goto FREEREADBUF; // unlink the output file and free read_buffer
    }
    memset(decrypt_buffer, 0, PAGE_SIZE);

    size_t bytesRead = 0;
    size_t readSize = (size_t) PAGE_SIZE;

    bytesRead = inputFile->f_op->read(inputFile, read_buffer, 16, &inputFile->f_pos);
    printk(" The hashed password value read is: "); print_md5(read_buffer);

    ret = memcmp(read_buffer, msgDigest, 16);
    if( ret != 0)
    {
        ret = -EINVAL;
        printk("Incorrect key provided to decrypt");
        goto FREEWRITEBUF; // free read write and del output file
    }

    while(true)
    {
        bytesRead = 0;
        memset(read_buffer, 0, PAGE_SIZE);
        memset(decrypt_buffer, 0, PAGE_SIZE);
   
        bytesRead = inputFile->f_op->read(inputFile, read_buffer, PAGE_SIZE, &inputFile->f_pos);
        if(bytesRead < 0)
        {
           // if less than 0 free read buffer, write buffer and felete output file
            ret = -EIO;
            goto FREEWRITEBUF;
        }
        if(bytesRead == 0)
        {
            goto FREEWRITEBUF;
        }

        pageCount++;
        printk("Decrypting %d bytes", bytesRead);
        char aesIV[17];
        memset(aesIV, 0, 17);
        getAESinstantiationVector(aesIV, pageCount);
        printk("my inst vector: ");print_md5(aesIV);

        readSize = bytesRead;
        ret = ceph_aes_decrypt(keybuf, keylen, decrypt_buffer,&readSize, read_buffer, bytesRead, aesIV);
        if( ret < 0)
        {
            printk(" decryption failed in kernel ");
            goto FREEWRITEBUF;
        }

        if(outputFile->f_op->write(outputFile, decrypt_buffer, readSize, &outputFile->f_pos) <=0)
        {
            ret = -EIO;// if writing failed, free read buffer, write buffer and felete output file
            goto FREEWRITEBUF;
        }

    }

FREEWRITEBUF:
    if(decrypt_buffer)
        kfree(decrypt_buffer);
FREEREADBUF:
    if(read_buffer)
        kfree(read_buffer);
DELOUTFILE:
    if( ret != 0)
        deleteFile(outputFile);

    set_fs(oldfs);
    return ret; 
}

/*
 * Do encryption or decryption based on the flag
 * generate message digest of the key provided
 */
long doxcrypt(struct file* inputFile,struct file* outputFile, void* keybufCopy, int keylen, int flags)
{

    printk(" In the xcrypt function \n ");
    long ret = 0;
  
    if(inputFile == NULL)
        return -EINVAL;

    if(outputFile == NULL)
        return -EINVAL;

    if(keybufCopy == NULL)
        return -EINVAL;


    mm_segment_t oldfs;
    oldfs = get_fs();// store the prev transalation so that we dont mess later
    set_fs(KERNEL_DS);// the read_buffer points to kernel , no need of translation
  
    // calculate the message digest 

    char messageDigest[17];
    memset(messageDigest, 0, 17);
    ret = calculate_md5(messageDigest, keybufCopy, keylen);
    if(ret != 0)
    {
        goto OUT;
    }
    printk(" The key :"); print_md5(keybufCopy);printk(" msg digest: ");print_md5(messageDigest);

    if(flags == ENCRYPT)
    {
        // call encrypt
        ret =  doEncrypt(inputFile, outputFile, messageDigest, keylen, keybufCopy);  
    }else if(flags == DECRYPT)
    {
        // call decrypt
        ret =  doDecrypt(inputFile, outputFile, messageDigest, keylen, keybufCopy);
    }
    else
    {
        // invalid flag value
        ret = -EINVAL;
    }

OUT:  
    set_fs(oldfs);// restore the prev translation
    return ret;
}

/*
 * Check if the user provided arguments belong to the user space and are  valid physical memory locations 
 * may be redundant, as copyfromuser also does a access check
 */
long isArgsValid(void* args)
{
    if (args == NULL)
    {
        return -EINVAL;
    }

    struct xcryptargs* cargs = (struct xcryptargs*)args; 

    if(cargs->infile == NULL || cargs->outfile == NULL || cargs->keybuf == NULL || cargs->keylen == 0)
        return -EINVAL;

    if(!access_ok(VERIFY_READ, cargs->infile, sizeof(cargs->infile)))
    {
        return -EFAULT;
    }
     
    if(!access_ok(VERIFY_READ, cargs->outfile, sizeof(cargs->outfile)))
    {
        return -EFAULT;
    }

    if(!access_ok(VERIFY_READ, cargs->keybuf, sizeof(cargs->keybuf)))
    {
        return -EFAULT;
    }

    return 0; 
    
}

/*
 * Copy the data from userland to kernel land
 * No matter how big the user key is , it is always truncated to 16 bytes
 * If the key provided is less than 16, an error is thrown to the user
 * also we check for filenames exceeding max path length
 */
long copyFromUserland(struct xcryptargs* userArgs, struct xcryptargs* kernelArgs)
{
    long ret = 0;
    printk("in copy from userland\n");

    // copy the input file
    // strlen_user copies the null byte as well
    if(strlen_user(userArgs->infile)-1 >= PATH_MAX)
    {
        ret = ENAMETOOLONG;
        goto OUT;
    }
    kernelArgs->infile = kmalloc(strlen_user(userArgs->infile), GFP_KERNEL);
    if(kernelArgs->infile == NULL)
    {
        ret = -ENOMEM;
        goto OUT;
      
    }
    memset(kernelArgs->infile, 0,strlen_user(userArgs->infile));
    if(copy_from_user(kernelArgs->infile, userArgs->infile, strlen_user(userArgs->infile)) != 0)
    {
        ret = -EFAULT;
        goto OUT;// free infile
    }


    // copy the output file
    if(strlen_user(userArgs->outfile)-1 >= PATH_MAX)
    {
        ret = ENAMETOOLONG;
        goto OUT;
    }
    kernelArgs->outfile = kmalloc(strlen_user(userArgs->outfile), GFP_KERNEL);
    if(kernelArgs->outfile == NULL)
    {
        ret = -ENOMEM;
        goto OUT;// free infile

    } 
    memset(kernelArgs->outfile, 0,strlen_user(userArgs->outfile));
    if(copy_from_user(kernelArgs->outfile, userArgs->outfile, strlen_user(userArgs->outfile)) != 0)
    {
        ret = -EFAULT;
        goto OUT;// FREE infile and outfile
    }


    // copy the key  buffer
    kernelArgs->keybuf = kmalloc( MD5_DIGEST_LENGTH, GFP_KERNEL);
    if(kernelArgs->keybuf == NULL)
    {
        ret = -ENOMEM;
        goto OUT;// free infile and outfile

    }
    memset(kernelArgs->keybuf, 0, MD5_DIGEST_LENGTH);
    if(copy_from_user(kernelArgs->keybuf, userArgs->keybuf, MD5_DIGEST_LENGTH) != 0)
    {
        ret = -EFAULT;
        goto OUT; // free infile, outfile and keybuff
    }

    // copy the key length
    if(copy_from_user(&kernelArgs->keylen, &userArgs->keylen, sizeof(int)) != 0)
    {
        ret = -EFAULT;
        goto OUT; // free infile, outfile and keybuff
    }

    if(strlen_user(userArgs->keybuf)-1 != kernelArgs->keylen)
    {
        printk(" user passed buffer length and passed keylength do not match");
        ret = -EFAULT;
        goto OUT; // free infile, outfile and keybuff
    }

    // check if keylen is less than 16
    if( kernelArgs->keylen < MD5_DIGEST_LENGTH)
    {
        printk(" key passed less than 128 bits");
        ret = -EINVAL;
        goto OUT; 
    }
  
    // copy the flags
    if(copy_from_user(&kernelArgs->flags, &userArgs->flags, sizeof(int)) != 0)
    {
        ret = -EFAULT;
        goto OUT;
    }

    // look only at the LSB
    kernelArgs->flags = kernelArgs->flags & 1;
    if(kernelArgs->flags < 0 || kernelArgs->flags > 1) // though the o/p produce either 0 or 1, this check may be redundant
    {
        printk(" invalid flag value");
        ret = -EINVAL;
        goto OUT;
    }
    // Exit from the function; free all of them if allocated in the end
OUT:
    return ret;
}


/*
 *  checks if the two files have identical inodes in same super block
 */
bool isIpFileEqualsOpFile( struct file* infile, char* outfile)
{
    struct file *filp = NULL;

    if(infile == NULL || outfile == NULL)
    {
        return false;
    }

    umode_t inMode = infile->f_path.dentry->d_inode->i_mode;
    filp = filp_open(outfile, O_RDONLY|O_WRONLY, inMode);

    if (!filp || IS_ERR(filp)) 
    {
        return false;
    }

    // this means the output file exists, check if equal to input file
    // check if the inode numbers are same in the same super block
    if((infile->f_path.dentry->d_inode->i_ino == filp->f_path.dentry->d_inode->i_ino) &&
       (infile->f_path.dentry->d_inode->i_sb == filp->f_path.dentry->d_inode->i_sb))
    {
        printk(" input and out put files are same \n");
        return true;
    }

    return false;
}

/*
 *Renames the tempOutputFilep to outfile
 */
int doRename(struct file* tempOutputFilep, char* outfile)
{
    int ret = 0;
    struct file* outfilep = checkOutputFile(outfile, tempOutputFilep);
    if(outfilep == NULL)
    {
        ret = -EPERM;
        goto OUT;
    }

    if(!(tempOutputFilep))
    {
        ret = -EINVAL;
        if(outfilep)
            filp_close(outfilep, NULL);
        goto OUT;    
    }

    printk(" Starting to rename \n");
    struct inode* old_file = tempOutputFilep->f_path.dentry->d_parent->d_inode;
    struct dentry* old_dentry = tempOutputFilep->f_path.dentry;
    struct inode* new_file = outfilep->f_path.dentry->d_parent->d_inode;
    struct dentry* new_dentry =  outfilep->f_path.dentry;
   

    if(tempOutputFilep)
        filp_close(tempOutputFilep, NULL);// this may fail?

    if(outfilep)
        filp_close(outfilep, NULL);// this may fail?
 
    ret = vfs_rename(old_file, old_dentry, new_file, new_dentry, NULL, 0);

OUT:
    return ret;

}


bool isDir(char* file)
{
    struct file *filp = NULL;
  
    filp = filp_open(file, O_RDONLY, 0);

    if (!filp || IS_ERR(filp))
    {
        return false;
    }

    // now that i have file pointer, check if its directory
    if(S_ISDIR(filp->f_path.dentry->d_inode->i_mode))
    {
        // before returning close the file pointer
        printk(" file specified is a directory\n");
        filp_close(filp, NULL);
        return true;
    }

    filp_close(filp, NULL);
    return false;
  
}

/*
 * Heart of the logic. Initiates the encryption/decryption module
 */
long sys_xcrypt(char* infile, char* outfile, char* keybuf,int keylen, int flags)
{
    long ret = 0;

    // truncating key to only 16 bits
    char paswordDigest[17];
    memset(paswordDigest, 0, 17);
    paswordDigest[16] = '\0';
    memcpy(paswordDigest, keybuf, 16);

    // check if input file exists and validate it
    struct file* inputFile = checkInputFile(infile, &ret);
    if(inputFile == NULL)
    {
        goto OUT; 
    }

    // check if output file is same as input file
    if(isIpFileEqualsOpFile(inputFile, outfile))
    {
        ret = -EINVAL;
        goto FREEINPUTFILE;
    }

    // check if outfile is a directory, throw err without creating temp
    if(isDir(outfile))
    {
        ret = -EISDIR;
        goto FREEINPUTFILE;
    }   

    // Now create a temp output file
    char* tempOutputFile = (char*) kmalloc(PAGE_SIZE, GFP_KERNEL); // page size coz of max path length
    if(tempOutputFile == NULL)
    {
        ret = -ENOMEM;
        goto FREEINPUTFILE;
    }
    memset(tempOutputFile, 0, PAGE_SIZE);
    strcat(tempOutputFile, outfile);// TODO: what if the file name or path is max
    strcat(tempOutputFile, ".tmp");
    printk(" my temp file of file name len %d: %s\n", strlen(tempOutputFile), tempOutputFile);
    // input file is good, now see if you want to open or create output file
    // you have to create output file with permissions of printk("input file size: %d\n", strlen(kCryptArgs->infile));
    struct file* tempOutputFilep = checkOutputFile(tempOutputFile, inputFile);
    if( tempOutputFilep == NULL)
    {
         // set return value;free inputFile, temp output file and kernel args
         ret = -EPERM;
         goto FREETEMPOUTFILE;
    }

    // now do xcrypt depending  upon the flag
    ret = doxcrypt(inputFile, tempOutputFilep, paswordDigest, MD5_DIGEST_LENGTH, flags);
    if( ret == 0)
    {
        // rename the temp output file into output file
        printk(" renaming %s to %s\n",tempOutputFile, kCryptArgs->outfile);
        printk("output file size: %d\n", strlen(kCryptArgs->outfile));
        ret = doRename(tempOutputFilep, outfile);
        if(ret == 0)
               printk("File renamed successfully");
     
    }

    if(tempOutputFilep)
        filp_close(tempOutputFilep, NULL);

FREETEMPOUTFILE:
    if(tempOutputFile)
        kfree(tempOutputFile);
FREEINPUTFILE:
    if(inputFile)
        filp_close(inputFile, NULL);

OUT:
    return ret;
    
}

asmlinkage extern long (*sysptr)(void *arg);

/*
 * Entry point of the system call
 * checks the user provided arguments, copies into kernel and triggers the functionality
 */
asmlinkage long xcrypt(void *arg)
{
    long retVal = 0;
    // validate arguments: user passed arguments are of the struct type xcryptargs
    retVal = isArgsValid(arg);
    if(retVal != 0)
        goto LAST;
          
    // all args are valid user virtual memory locations  and hold good values
    // now copy the data from user space to kernel space
    kCryptArgs = (struct xcryptargs*)kmalloc(sizeof(struct xcryptargs), GFP_KERNEL);// dont forget to free kCryptArgs
    if(kCryptArgs == NULL)
    {
        retVal = -ENOMEM;
        goto LAST;
    }
    // fill in the struct with all zeros
    memset(kCryptArgs, 0, sizeof(struct xcryptargs));
    // start copying
    retVal = copyFromUserland(arg, kCryptArgs);
    if(retVal != 0)
    {
         goto FREEARGS;// free kCryptargs
    }
       
    // kernel level copy done. 
    printk("xcrypt received input file: %s\n",kCryptArgs->infile);
    printk("xcrypt received outputfile: %s\n",kCryptArgs->outfile);
    printk("recieved key at kernel: ");print_md5(kCryptArgs->keybuf);
    printk("xcrypt received keylen: %d\n",kCryptArgs->keylen);
    printk("xcrypt received flags: %d\n",kCryptArgs->flags);

    retVal = sys_xcrypt(kCryptArgs->infile, kCryptArgs->outfile, kCryptArgs->keybuf, kCryptArgs->keylen, kCryptArgs->flags);

FREEARGS:
   if(kCryptArgs->infile)
       kfree(kCryptArgs->infile);
   if(kCryptArgs->outfile)
       kfree(kCryptArgs->outfile);
   if(kCryptArgs->keybuf)
       kfree(kCryptArgs->keybuf);
   if(kCryptArgs)
       kfree(kCryptArgs);

LAST:
  return retVal;

} 

static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
