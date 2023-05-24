package main

// Date:    17/05/2023

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

var (
	partial_ext   string = ".partially.plutocrypt"
	full_ext      string = ".fully.plutocrypt"
	exe_ext       string = ".exe" + partial_ext
	originalSeq_b []byte
	encText_b     []byte
	key_b         []byte
	error_chan    chan error
)

func main() {
	originalSeq_b = []byte{105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101}
	encText_b = make([]byte, 20)
	key_b = make([]byte, 20)

	error_chan = make(chan error)
	go handleError()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalln("Error while getting user home dir:", err)
	}
	fmt.Println("PlutoCrypt decryptor by PRODAFT")
	fmt.Println("ABSOLUTELY NO WARRANTY")
	// Finding a suitable EXE file
	foundFlag := false
	err = filepath.Walk(homeDir,
		func(path string, info fs.FileInfo, err error) error {
			if len(path) > len(exe_ext) && !foundFlag {
				if path[len(path)-len(exe_ext):] == exe_ext {
					//open encrypted exe file
					file, err := os.Open(path)
					if err != nil {
						error_chan <- err
						return nil
					}
					file_stat, err := file.Stat()
					if err != nil {
						error_chan <- err
						return nil
					}
					if file_stat.Size() < 100 {
						return nil
					}
					file.ReadAt(encText_b, 80)
					for i := 0; i < 20; i++ {
						key_b[i] = encText_b[i] - originalSeq_b[i]
					}
					// check for the validity of key
					file.ReadAt(encText_b, 0)
					first_two, err := decrypt_bytes(encText_b[:2])
					if err != nil {
						error_chan <- err
						return nil
					}
					if first_two[0] != 0x4D || first_two[1] != 0x5A {
						return nil
					}
					fmt.Println("Found the key:", key_b)
					foundFlag = true
					return nil
				}
			}
			return nil
		})
	if err != nil {
		log.Println(err)
		log.Println("Execution Finished")
		fmt.Println("Press return(enter) to exit...")
		fmt.Scanln()
		return
	}
	if !foundFlag {
		log.Println("There is no file suitable for finding the key. No encrypted EXE file")

		log.Println("Execution Finished")
		fmt.Println("Press return(enter) to exit...")
		fmt.Scanln()
		return
	}

	del_enc_s := ""
	for del_enc_s != "yes" && del_enc_s != "no" {
		fmt.Print("Do you want to delete the encrypted files after recovering the original? [yes/no]")
		fmt.Scanln(&del_enc_s)
	}
	if err != nil {
		panic(err)
	}

	decrypt_folder(homeDir, del_enc_s == "yes")
	decrypt_folder(`D:\`, del_enc_s == "yes")
	decrypt_folder(`E:\`, del_enc_s == "yes")
	decrypt_folder(`F:\`, del_enc_s == "yes")
	decrypt_folder(`G:\`, del_enc_s == "yes")
	decrypt_folder(`H:\`, del_enc_s == "yes")
	decrypt_folder(`B:\`, del_enc_s == "yes")

	log.Println("Execution Finished")
	fmt.Println("Press return(enter) to exit...")
	fmt.Scanln()
}

func handleError() {
	errfile, _ := os.Create("plutocrypt_decryptor_err.log")
	for err := range error_chan {
		log.Println("ERR:", err)
		errfile.Write([]byte("ERR:" + err.Error() + "\n"))
	}
}

func decrypt_folder(folder string, delete bool) error {
	return filepath.Walk(folder,
		func(path string, info fs.FileInfo, err error) error {
			if isPartial(path) {
				created, err := os.Create(path[:len(path)-len(partial_ext)])
				if err != nil {
					error_chan <- err
					return nil
				}
				defer created.Close()
				fmt.Println("Decrypting the file:", path)
				encrypted, err := os.Open(path)
				if err != nil {
					error_chan <- err
					return nil
				}
				defer encrypted.Close()

				first1024 := make([]byte, 1024)
				encrypted.Read(first1024)

				dec, err := decrypt_bytes(first1024)
				if err != nil {
					error_chan <- err
					return nil
				}

				created.Write(dec)
				// read the rest
				io.Copy(created, encrypted)
				if delete {
					encrypted.Close()
					err := os.Remove(path)
					if err != nil {
						error_chan <- err
						return nil
					}
				}

			} else if isFull(path) {
				created, err := os.Create(path[:len(path)-len(full_ext)])
				if err != nil {
					error_chan <- err
					return nil
				}
				fmt.Println("Decrypting the file:", path)
				encrypted, err := os.Open(path)
				if err != nil {
					error_chan <- err
					return nil
				}
				buf := make([]byte, len(key_b))
				enc_f_stats, err := encrypted.Stat()
				if err != nil {
					error_chan <- err
					return nil
				}

				filesize := enc_f_stats.Size()
				processed := 0
				for processed < int(filesize) {
					nr, _ := encrypted.Read(buf)
					dec, err := decrypt_bytes(buf[:nr])
					if err != nil {
						error_chan <- err
						return nil
					}
					created.Write(dec)
					processed += nr
				}

				if delete {
					encrypted.Close()
					err := os.Remove(path)
					if err != nil {
						error_chan <- err
						return nil
					}
				}
			}
			return nil
		})

}

func decrypt_bytes(in []byte) ([]byte, error) {
	keylen := len(key_b)
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = b - key_b[i%keylen]
	}

	return out, nil
}

func isPartial(path string) bool {
	if len(path) < len(partial_ext) {
		return false
	}
	return path[len(path)-len(partial_ext):] == partial_ext
}
func isFull(path string) bool {
	if len(path) < len(full_ext) {
		return false
	}
	return path[len(path)-len(full_ext):] == full_ext
}
