# Look into the past

April 27, 2020

**Task:** *We've captured a snapshot of a computer, but it seems the user was able to encrypt a file before we got to it. Can you figure out what they encrypted?*

In my opinion, this was one of the most interesting challences of this CTF as it was a mix of a few different sub-challenges to solve.

We were given a snapshop of a computer, in .tar format. After downloading it, we extracted its content:
```console
root@kali:~# tar xvf look_into_the_past.tar 
```

Sure enough, the archive contained a computer snapshot with most usual folders that we find on linux hosts:

```console
root@kali:~# ll look_into_the_past
total 80
drwxr-xr-x 20 bob  bob  4096 Feb  8 11:24 .
drwxr-xr-x  6 root root 4096 Apr 30 02:07 ..
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 bin
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 boot
drwxr-xr-x  8 bob  bob  4096 Feb  8 11:24 dev
drwxr-xr-x 97 bob  bob  4096 Feb  8 11:24 etc
drwxr-xr-x  3 bob  bob  4096 Feb  8 11:24 home
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 lib
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 media
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 mnt
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 opt
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 proc
drwxr-xr-x  3 bob  bob  4096 Feb  8 11:24 root
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 run
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 sbin
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 srv
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 sys
drwxr-xr-x  2 bob  bob  4096 Feb  8 11:24 tmp
drwxr-xr-x 13 bob  bob  4096 Feb  8 11:24 usr
drwxr-xr-x  9 bob  bob  4096 Feb  8 11:24 var
```

Given the title of the challenge "Look into the past", we first thought that we should go check the logs, in `/var/log` but that folder was empty. So the next interesting place to check out was the `/home/` folder.

Bingo!

```console
root@kali:~/look_into_the_past/home/User# ll
total 52
drwxr-xr-x 9 bob bob 4096 Feb  8 11:24 .
drwxr-xr-x 3 bob bob 4096 Feb  8 11:24 ..
-rw-r--r-- 1 bob bob  349 Feb  6 13:33 .bash_history
-rw-r--r-- 1 bob bob  864 Feb  6 13:34 .bashrc
drwxr-xr-x 2 bob bob 4096 Feb  8 11:24 Desktop
drwxr-xr-x 2 bob bob 4096 Feb  8 11:52 Documents
drwxr-xr-x 2 bob bob 4096 Feb  8 11:24 Downloads
drwxr-xr-x 2 bob bob 4096 Feb  8 11:24 Music
drwxr-xr-x 2 bob bob 4096 Feb  8 11:24 Pictures
-rw-r--r-- 1 bob bob  672 Feb  6 13:34 .profile
drwxr-xr-x 2 bob bob 4096 Feb  8 11:24 Public
drwxr-xr-x 2 bob bob 4096 Feb  8 11:24 Videos
-rw-r--r-- 1 bob bob   37 Feb  6 13:33 .vimrc
```

We went through all of these folders and found that only **Documents** and **Pictures** were of interest.
Also, we checked the `.bash_history` file for any interesting information and found a few clues. Obviously, "Look into the past" meant to go check out the bash history.

## .bash_history

This is the full dump of what was in the `.bash_history` file:

```console
root@kali:~/look_into_the_past/home/User# more .bash_history 
cd Documents
openssl enc -aes-256-cbc -salt -in flag.txt -out flag.txt.enc -k $(cat $pass1)$pass2$pass3
steghide embed -cf doggo.jpeg -ef $pass1 
mv doggo.jpeg ~/Pictures
useradd -p '$pass2'  user
sqlite3 /opt/table.db "INSERT INTO passwords values ('1', $pass3)"
tar -zcf /opt/table.db.tar.gz /opt/table.db
rm $pass1
unset $pass2
unset $pass3
exit
```

## Documents

```console
root@kali:~/look_into_the_past/home/User# ll Documents/
total 16
drwxr-xr-x 2 bob bob 4096 Feb  8 11:52 .
drwxr-xr-x 9 bob bob 4096 Feb  8 11:24 ..
-rw-r--r-- 1 bob bob   48 Feb  8 11:50 flag.txt.enc
-rw-r--r-- 1 bob bob   48 Feb  6 13:33 libssl-flag.txt.enc
root@kali:~/look_into_the_past/home/User# 
```

Hurray! There's our flag! Ok, so, obviously it's encoded and they're not going to make it easy for us to read that file.
Using the `File` command, we learned that both files were openssl encoded, with salt:

```console
root@kali:~/look_into_the_past/home/User/Documents# file *
flag.txt.enc:        openssl enc'd data with salted password
libssl-flag.txt.enc: openssl enc'd data with salted password
```

How are we going to decode this? We need to look for more clues.

## Pictures

In this folder, there was a picture of a lovely dog, and a hidden previous version of the same picture:

```console
root@kali:~/look_into_the_past/home/User/Pictures# ll
total 36
drwxr-xr-x 2 bob bob  4096 Feb  8 11:24 .
drwxr-xr-x 9 bob bob  4096 Feb  8 11:24 ..
-rw-r--r-- 1 bob bob  4096 Feb  8 11:24 ._doggo.jpeg
-rw-r--r-- 1 bob bob 21404 Feb  6 13:33 doggo.jpeg
```

This is what the image looked like, not much help here:
![Doggo](doggo.jpeg)

So what do we do with images usually in CTFs? Of course we're tempted to search for hidden messages!
