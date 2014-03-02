package main

import (
  "fmt"
  "os"
  "strconv"
  "bytes"
  "github.com/codegangsta/cli"
  "io/ioutil"
  "code.google.com/p/gopass"
  "github.com/tadzik/simpleaes"
  "crypto/rand"
)

func main() {
  app := cli.NewApp()
  app.Name = "password_store"

  app.Flags = []cli.Flag {
    cli.StringFlag{"key", "your_key", "secret key for your passwords"},
  }

  app.Commands = []cli.Command{
    {
      Name:      "set",
      ShortName: "s",
      Usage:     "set a password for a domain: password_store set test.com",
      Action: func(c *cli.Context) {
        if len(c.Args()) < 1 || len(c.Args()) > 3 {
          fmt.Println("set requires 1 parameter: password_store set test.com")
          os.Exit(1)
        }
        domain := c.Args()[0]

        password_length := 20
        if len(c.Args()) == 2 {
          password_length, _ = strconv.Atoi(c.Args()[1])
        }

        passed_key := ""
        if len(c.Args()) == 3 {
          passed_key = c.Args()[2]
        }

        key, _ := get_key(passed_key)
        password := random_string(password_length)

        err := store_password(domain, password, key)
        if err != nil {
          panic(err)
        }

        fmt.Println("Password saved successfull for", domain, ":", password)
      },
    },
    {
      Name:      "get",
      ShortName: "g",
      Usage:     "get a password for a domain",
      Action: func(c *cli.Context) {
        if len(c.Args()) < 1 || len(c.Args()) > 2 {
          fmt.Println("get requires 1 parameter: password_store get test.com")
          os.Exit(1)
        }

        domain := c.Args()[0]

        passed_key := ""
        if len(c.Args()) == 2 {
          passed_key = c.Args()[1]
        }

        key, _ := get_key(passed_key)

        password, err := fetch_password(domain, key)
        if err != nil {
          panic(err)
        }

        fmt.Println("Password for", domain, ":", password)
      },
    },
  }

  app.Run(os.Args)
}

func store_password(domain string, password string, key string) (error) {
  filename := "/var/password_store/passwords/" + domain
  encrypted_pass, err := encrypt(password, key)
  if err != nil {
    panic(err)
  }

  err = ioutil.WriteFile(filename, []byte(encrypted_pass), 0644)
  return err
}

func fetch_password(domain string, key string) (string, error) {
  filename := "/var/password_store/passwords/" + domain
  encrypted_pass, err := read_file(filename)
  if err != nil {
    panic(err)
  }

  decrypted_pass, err := decrypt(encrypted_pass, key)
  non_nil_pass := bytes.Trim([]byte(decrypted_pass), "\x00")

  return string(non_nil_pass), nil
}

func get_key(key string) (string, error) {
  if len(key) == 0 {
    key, _ = gopass.GetPass("secret key:")
  }

  for len(key) < 16 {
    key += "_"
  }

  return key, nil
}

func read_file(filename string) (string, error) {
  file_content, err := ioutil.ReadFile(filename)
  if err != nil {
    if os.IsNotExist(err) {
      return "Not found", nil
    } else {
      return "", err
    }
  }
  return string(file_content), nil
}

func encrypt(str string, key string) (string, error) {
  aes, err := simpleaes.New(16, key)
  if err != nil {
    panic(err)
  }

  buf := aes.Encrypt([]byte(str))

  return string(buf), nil
}

func decrypt(encrypted string, key string) (string, error) {
  aes, err := simpleaes.New(16, key)
  if err != nil {
    panic(err)
  }

  buf := aes.Decrypt([]byte(encrypted))

  return string(buf), nil
}

func random_string(n int) string {
  const available_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_-+=~`?/.,<>"
  var bytes = make([]byte, n)
  rand.Read(bytes)
  for i, b := range bytes {
    bytes[i] = available_chars[b % byte(len(available_chars))]
  }
  return string(bytes)
}

