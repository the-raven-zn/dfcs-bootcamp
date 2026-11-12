# File Upload Security — Remediation Brief
**For:** Management / Non-Technical Stakeholders
**Prepared by:** Muhammad Zain Nasir
**Subject:** Critical weakness found in the file upload feature

## What we found

The web application's file upload feature does not properly check what
people are allowed to submit. During testing, our team was able to
upload a disguised file through the upload form and get the server to
run it as a program — giving us the same level of access to the server
that the website's own software has.

This is one of the most serious types of weakness a web application
can have, because it does not require tricking a user or stealing a
password. Anyone who can reach the upload form can potentially do this.

## Why it matters

Once a file like this runs on the server, an attacker can:
- Read configuration files, which often contain database passwords
- View, change, or delete data stored in the application's database
- Use the server as a stepping stone to reach other systems on the
  same network
- Leave a permanent foothold that keeps working even after the
  original weakness is noticed, unless it is specifically found and
  removed

We confirmed this is possible, measured how far it goes, and tested it
against three different levels of built-in protection in the test
environment. The weakest protection level offered no resistance at
all. A protection that only checks the file type that the browser
claims — which is one of the three protections we tested — can be
defeated because that claim is something the person uploading
controls and can simply change before it reaches the server. A
stronger protection that checks the uploaded content more carefully
still let a disguised file through, because it did not verify the
content closely enough and because the storage location still allowed
certain file types to run as programs.

## What needs to change

1. **Check the actual content of every uploaded file on the server**,
   not just its declared type or the end of its filename. The server
   should confirm a file really is what it claims to be before
   accepting it.
2. **Never trust the filename the user provides.** Store uploaded
   files under a new, randomly generated name so an attacker cannot
   predict or request their file directly.
3. **Store uploaded files somewhere the server will never run as a
   program**, regardless of what the file contains or is named. This
   single change would have stopped every method we tested, even the
   ones that got past the content checks.
4. **Make browsers download files instead of running or displaying
   them** when a user opens an uploaded file's link directly.
5. **Limit the size and rate of uploads**, and **log any file whose
   content doesn't match the type it claims to be**, so unusual
   activity is visible instead of silent.

## Priority

This should be treated as an urgent fix, not routine maintenance. The
underlying weakness gives an outside party the same level of control
over the server as the application itself has — there is no
intermediate step an attacker needs to take first.
