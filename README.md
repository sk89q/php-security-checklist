# PHP Security Checklist

This work was [originally published on sk89q.com in 2009](http://www.sk89q.com/2009/08/definitive-php-security-checklist/). It is licensed under a [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-nc-sa/4.0/).

[![Creative Commons License](https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)](http://creativecommons.org/licenses/by-nc-sa/4.0/)  

## Basic

*   Have strong passwords be sure that your “password recovery questions” are not too obvious.
    *   If you write down your passwords, ensure that you put it in a safe place.
*   Make sure that [register_globals](http://php.net/register_globals) is disabled, because that allows arbitrary variables to be injected into your script’s environment (!).
*   Disable magic quotes. It has no effect on security, but it leads people to think that it actually helps secure applications against SQL injection, and so people rely on it for escaping (highly wrong!). The two relevant PHP settings are [magic_quotes_gpc](http://php.net/magic_quotes_gpc) and [magic_quotes_runtime](http://php.net/magic_quotes_runtime).
*   Disable [display_errors](http://php.net/display_errors) on your production environment to make it more difficult to learn details about your environment. You should continue to log errors, however.
*   Don’t forget about the physical security of your server(s). Make sure you’re in a secure data center (hint: some are grossly insecure).
*   User input and non-uploaded content:
*   Be aware that you can initiate a request from something as simple as telnet, so that means that **all** incoming data can be forged.
    *   This means that everything in $_GET, $_POST, $_COOKIE, and $_REQUEST can all contain any value.
    *   $_SERVER and $_ENV are a bit different: some values come from the web server, while others come from the client.
        *   $_SERVER['PHP_SELF'] is not entirely safe, as URLs can be, depending on your configuration, cleverly constructed to contain arbitrary data and yet still work.
*   Filter and validate data to make sure that it is safe for the environment that you are using the data in.
    *   Be aware that incoming data can contain control characters such as _null_. Null signifies the end of a string in C/C++, so you can imagine what could happen if you are passing a PHP string to another program or the system API.
    *   Check the length of inputted data to make sure that it is not too long.
    *   Make sure to validate email addresses, because it is possible to inject email headers by crafting specially constructed email addresses.
        *   Email address validation is fairly complicated. “John Doe”@example.com is actually a valid email address (quotation marks and space included). You can validate email addresses by using [filter_var](http://php.net/filter_var)() with [FILTER_VALIDATE_EMAIL](http://php.net/manual/en/filter.filters.validate.php) (do not use the [sanitization version](http://php.net/manual/en/filter.filters.sanitize.php)), a [sufficiently inclusive validation regex](http://www.regular-expressions.info/email.html) (catching most email address use cases), or a [fully compliant regex](http://www.ex-parrot.com/pdw/Mail-RFC822-Address.html).
    *   Don’t forget that inputted numbers can be very large, very small, zero, or negative. You don’t want to deposit a negative number of credits!
    *   Be aware that some character sets (namely Unicode) have “invisible” characters, characters that look alike, or different ways of [combining characters](http://en.wikipedia.org/wiki/Combining_characters) (for diacritics, namely). This could be used to impersonate another user.
        *   Some character sets also contain layout control characters (namely Unicode), which could be used to modify the layout of the page slightly.
*   Before outputting data to the browser, make sure to properly escape it to prevent [cross-site scripting](http://en.wikipedia.org/wiki/Cross-site_scripting) (XSS). As a general rule, **use a white list, never a black list**.
    *   If you are allowing the user to use (some) HTML, it is important that you use a very secure HTML sanitizer ([HTML Purifier](http://htmlpurifier.org/) is recommended).
        *   There are **many many** ways to achieve the same result in HTML, so don’t try to do HTML sanitizing yourself (seriously, just forget it).
    *   If CSS is allowed, then that must be sanitized as well.
        *   Be aware that certain CSS properties such as “position” could be used maliciously (elements overlaying login forms, etcetera).
        *   CSS can also contain escape sequences both inside and outside strings (`\34`).
        *   CSS files can contain JavaScript. This manifests itself in the form of “CSS expressions” and “behaviors” (Internet Explorer features) or Gecko “bindings.”
    *   Check to make sure that any user-supplied URLs are valid and safe. URLs to websites, URLs to images, etc.
        *   Be aware of the different protocols: http:, https:, ftp:, ftps:, gopher:, 3rd-party ones such as [aim:](http://en.wikipedia.org/wiki/Aol_Instant_Messenger), and [data:](http://en.wikipedia.org/wiki/Data_URI_scheme).
    *   If you allow users to embed plugins (i.e. Flash movies), make sure you embed it in a way where a different plugin cannot be loaded (based on file type).
    *   Included Java applets, Flash movies, or other plugin content may be able to access the page by executing JavaScript, depending on the way that the content was embedded into the page.
*   Use a “safe” encoding for your page (such as ISO-8859-1) or otherwise verify that the content of inputted data to see if it valid (including if you use UTF-8). This is because certain invalid character sequences can cause the next character (the next character possibly being an important < or “) to be ignored in some encodings.
    *   You **must** specify the encoding, otherwise you allow the web browser to guess at the encoding, and leaving the possibility that it may switch to a “dangerous” encoding.
    *   Specify the encoding in an HTTP header and not in the HTML.

## Uploaded Files

*   Verify that the type of the file is what you expected.
    *   The mime type/file type in the $_FILES array is provided by the user and can contain any value. Not only can the provided mime type be spoofed, it could also just be wrong or be overly generic.  
         (Conclusion: The field is useless.)
    *   The best way to check whether the file is of the format you expected is to analyze the contents of the file.
        *   A simple file type check algorithm can be easily fooled by putting the minimum necessary parts of the file format to pass that check. For example, you could take the first 20 bytes of a PNG file and then append the contents of badvirus.vbs to the end, giving you a file that would easily pass through many filters. A more complicated filter is more computationally intensive to use, however, and the few benefits are usually not worth it.
        *   An alternative method to verify the format of the file is to re-save it. A PNG image could be re-saved using the [GD library](http://php.net/gd), for example. However, this can degrade the quality of the file, especially if JPEG is concerned.
    *   Be aware that some formats can contain arbitrary data and still be valid (think “comment fields” in some file types).
*   Verify that the size of the file is not too large.
    *   If you are using [MAX_FILE_SIZE](http://php.net/manual/en/features.file-upload.post-method.php), you still need to perform the check. Do not use the value of MAX_FILE_SIZE to check again, as this can be spoofed (remember that all input data is suspect).
    *   Make sure that you don’t allow uploaded files to completely take up all the space for your system, possibly causing grave consequences.
*   Be aware that uploaded files, even if valid, can still contain malicious content.
    *   Uploaded files may be or contain viruses. You can scan for viruses if you wish, although it does use up (possibly expensive) resources to do so.
    *   Uploaded HTML files can contain malicious JavaScript.
*   Don’t move uploaded files to web-accessible directories, as your web server may parse some files as executable code (i.e. an uploaded .php file). It also hampers your ability to restrict access to the files (as noted before about hiding files).
*   Do extensive path checks to make sure you do not serve a non-uploaded file.
*   Don’t execute/serve uploaded files with include(). This executes PHP code, as previously mentioned. Use [readfile](http://php.net/readfile)().
*   Serve all uploaded files as an attachment and never inline (it’s a HTTP header called “Content-Disposition”). This is because Internet Explorer will override the content type you tell it and guess on its own. PNG image? No! Internet Explorer says it’s a HTML file with JavaScript code.
    *   Send the “[X-Content-Type-Options](http://blogs.msdn.com/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx): nosniff” header. This only alleviates the problem for IE8 and above, but IE7 and below would still have the issue (so you still need to send files as attachments).
*   Avoid serving files with content types of “application/octet-stream,” “application/unknown,” or “text/plain” unless necessary.

## Database

*   When inserting inputted data into an SQL query, escape the data or use parameterized/prepared statements. The issue at hand is called [SQL injection](http://en.wikipedia.org/wiki/SQL_injection).
    *   Do **not** use addslashes() to escape data; use the function for your particular DBMS to escape data, because different databases escape differently.
    *   A good way to prevent SQL injection is to use [prepared statements](http://en.wikipedia.org/wiki/SQL_injection#Parameterized_statements). [PDO](http://php.net/pdo) supports prepared statements, among other libraries.
*   Lock down access permissions so that your application does not have excess privileges to the database (unnecessary write privileges, etc.).
*   Be aware that your DBMS may allow remote connections (by default), so disable that feature as necessary.

## Including and Serving Files

*   Never use user input directly in a pathname.
    *   Check for directory traversal.
    *   Check for [null poison bytes](http://en.wikipedia.org/wiki/Null_character#Security_exploit:_Poison_null_byte).
    *   Be aware of the “:” character, which is used on NTFS and Windows to access [alternate data streams](http://en.wikipedia.org/wiki/Alternate_Data_Streams#Microsoft).
    *   Be aware of [PHP streams](http://php.net/manual/en/book.stream.php), which allows you (and attackers) to access non-file-based resources with URIs like `http://example.com/badcode.txt`.
        *   Check to make sure that attackers can’t include a remote file containing PHP code.
*   You should not be merely hiding files in a web-accessible directory because people may guess URLs.
    *   This applies to hiding things based on the content of a GET or POST variable. Actually verifying the identity of the user and his or her authorization level is a much better approach.
*   When you need to get a remote file, do not use include(), as that will also execute any PHP code on the page. Use something such as [file_get_contents](http://php.net/file_get_contents)().

## Authentication and Authorization

*   Install a bad password throttling system to prevent [brute force attacks](http://en.wikipedia.org/wiki/Brute_force_attack).
    *   You should consider throwing up a CAPTCHA test before outright denying any further login attempts. Do that not for security reasons, but rather to make it less annoying for your more forgetful users.
*   Be aware that a malicious user can sniff for packets to get a user’s password. The only real solution to this problem is to use SSL. It is possible to setup your own challenge and response system, but it won’t protect users if they are also susceptible to a [man-in-the-middle attack](http://en.wikipedia.org/wiki/Man-in-the-middle_attack).
*   Don’t store a user’s password in a cookie when logging in, for obvious reasons. This may seem like an easy way to implement “remember me,” but it is a bad idea.
*   Hash stored passwords to make it harder for an attacker who has gained access to your database to get the raw password of users.
    *   Use [salts](http://en.wikipedia.org/wiki/Salt_%28cryptography%29) to make [rainbow tables](http://en.wikipedia.org/wiki/Rainbow_tables) ineffective. It is highly recommended that you use a different salt per user to make intrusion more difficult (you will have to store the individual salts). Salts should be sufficiently long and complex to be strong.
    *   Use the PHP [crypt](http://php.net/crypt)() function if possible, as it generates very good hashes. You want to use Blowfish or SHA and use a good number of rounds. Increasing the number of rounds causes the hash calculation to be more computationally expensive, making the hashes much harder to brute force. Because you don’t constantly generate hashes, the extra CPU required should not have a major impact.
    *   Don’t use MD5.
*   If you allow your users to input password recovery questions, make sure to remind users to not use questions with answers that can be easily guessed by someone else. People’s accounts have been lost due to this very reason.
*   Be careful with account recovery forms to not allow malicious users from discovering whether an email address is registered in your database. The only solution to this problem is to not let the user know whether the email address exists in the database when they use the password recovery form. An email always has to be sent in that situation.
*   Remember to throttle any page that sends emails to prevent a malicious user from using your script to abuse your application.

## Sessions and Cookies

*   Use only cookies for sessions, to prevent [session fixation](http://en.wikipedia.org/wiki/Session_fixation) (i.e. a malicious user sending a target user a link to use an existing session already under the control of the attacker) and [session hijacking](http://en.wikipedia.org/wiki/Session_hijacking) (i.e. leaking a session ID placed in the URL) attacks. If you are using the PHP sessions, there is a PHP setting named [session.use_only_cookies](http://php.net/manual/en/session.configuration.php#ini.session.use-only-cookies) that determines this behavior.
*   After a session is complete (“logout”), destroy its data and don’t just clear the cookie (a malicious user could otherwise just re-instate the cookie and use the session again).
*   When changing a user’s authorization level (i.e. from guest to a logged in user), destroy the old session and create a new session to make session fixation harder. This is because if the attacker has access to the session (for some reason), the old session will now become useless rather than get extra privileges.
*   Even if you are not in a shared hosting environment, if you use the same directory to store session files for two or more of your sites, then a session created on one website will be a valid session on another.

## Remote Websites

*   Be aware that other sites can conduct [cross-site request forgeries](/wiki/Cross-site_request_forgery "Cross-site request forgery"), and pass off as a logged in user (both GET and POST requests can be forged).
    *   Don’t rely on referrers to protect against CSRFs, because many Internet security programs block the referrer field or give it some dubious value (like “—“).
    *   Use tokens/keys with your forms to prevent CSRFs. Do this for important pages.
    *   Using POST for pages that perform actions helps mitigate the issue, although it is still possible to submit a POST request from a form automatically.
    *   Be aware that even material you host on your website can be used against you, because the content is already on your website, and thus there are no cross-domain sanctions.  
         Example: An avatar URL that loads your logout page.
*   Be aware that, while other websites cannot just read content off your pages, some files can be read remotely (such as .js files) by their nature (including them via SCRIPT tags, etcetera).
    *   Files that look like JavaScript files could possibly be read remotely.
    *   Don’t forget about your files that contain JSON.
*   Older versions (and possibly current) of Flash could play media files remotely and bypass referrer checks, because Flash Player did not send a referrer.
*   Be aware that information could be probed using the inclusion of a file on your server on a remote site.
    *   Be aware that the existence of a file could be detected using the “onerror” event of an image element.
    *   Pages that conditionally take a longer time to load could be detected on a remote website.
        *   Cached files will take a shorter time to load.
    *   The dimensions of images on you server can be detected on a remote website.
    *   CSS files can be included remotely, and although not read, if the CSS files are conditional, information could be garnered from how the attack site is changed with the inclusion of the CSS file. Rather than including a CSS file, an attacker could attempt to include an HTML file directly as well, because the CSS parsers in web browsers are fairly lax and will try their best.
    *   Some browsers allow a remote site to detect the frames within another site.
    *   Some browsers may throw a different error if you attempt to delete a non-existent variable in a frame contain a remote website than if you were to delete an existing variable.
    *   It is possible to detect whether a user has visited a URL by checking how the browser has styled the link (visited vs. unvisited styles).
*   Be aware that Internet Explorer allows a remote website to include another website in an inline frame but disable JavaScript and cookies to function inside the inline frame. This breaks frame break-out attempts.
*   Install frame busting code and send the X-Frame-Options header to protect against [UI redressing/clickjacking](http://en.wikipedia.org/wiki/Clickjacking). Frame bursting code won’t work in IE if the attacker’s website disabled JavaScript in an inline frame (see above), but that’s what the header is for. Older versions of IE are still left vulnerable.

## Miscellaneous

*   If you are using random numbers for security, be aware that you need to be using a cryptographically secure random number generator otherwise it is possible to guess the pattern of random numbers.
    *   Things such as account activation links and randomly generated secret IDs need to be generated using a cryptographically secure random generator. Basically anything that is random that needs to be kept secret needs to be generated using a secure PRNG.
    *   PHP does **not** provide a cryptographically secure random number generator. However, you can access /dev/urandom (*nix) or CAPICOM.Utilities.1 (Windows). For an example, see [this comment](http://php.net/manual/en/function.mt-rand.php#83655). You can also install the [Suhosin patch](http://hardened-php.net/suhosin/) instead.
*   Anything that consumes a lot of resources should be throttled and limited.
    *   Pages that conduct long or resource intensive operations should be throttled, so that performing a denial-of-service attack against you isn’t as simple as leaving 10 browser windows on auto-refresh.
    *   Check to make sure that pages that access remote resources (i.e. APIs, etc.) cannot be used to launch denial of service attacks against these remote resources by using your site as a proxy.
*   Don’t try to create your own encryption algorithm.
*   If you are calling external programs (i.e. [exec](http://php.net/exec)()), make sure that you escape the arguments.
*   If you using a page to redirect to other pages (or other sites), make sure that this cannot be abused.
*   Be aware that something could go wrong, and your PHP files may suddenly be exposed (it has happened to big name sites, such as Facebook and others). Take precautions to prevent this.
*   Don’t put configuration files or any critical files in a web accessible directory, especially if their content can be read via the browser.
*   If you need to protect files (for example, against a login), put the files into a non-web-accessible directory and route all files through a PHP script. (This has been touched on previously.)
*   Internet Explorer has an XSS filter that could possibly be exploited to prevent a piece of code in a page to be executed by passing that piece of code as a query parameter in the URL.

## Shared Host Security

*   Be aware that on many shared hosts, users can access the files of other users. It may not be doable via PHP, but it may be doable via PHP via CGI (or Perl, etc. via CGI).
    *   In shared hosts where security is slightly better, you should chmod your files so that users of other groups cannot access your files.
    *   Someone noted that I glossed over this issue. Okay, read that again: **users can access the files of other users**. That should be a major worry, and the best part is that _most PHP shared web hosts don’t secure their servers against this_. You should verify that the web host that you are working with has properly secured their environment, and if it hasn’t, you should move.
*   Be aware that IE6 allows header spoofing with XMLHttpRequest, including the spoofing of Host and Referer. If you are on a virtual host setup (which you likely are if you are on a shared host), then another site can spoof the Host header and thus send arbritrary requests to your website from another website on the same server. (IE6 does not allow cross-domain requests. It’s the fact that the Host header tells the web server which site to host if several sites are all on the same IP address.)
*   Be aware that other users on the same server may have the same IP address as your website or can access your website from 127.0.0.1.
*   Be aware that other users on the same server may be able to run a server on the same IP as your website but on a different port.
*   Be aware that other users are “not” remote as far as your database may be concerned.
*   Be aware that another user on the same server may be able to create a false session for use on your own site (because in many configurations, all session temporary files are stored in the same directory for all users).
    *   Consequently, that means that other users may also be able to read your session data.
    *   A session created on one site can be used on another as well.
*   File uploads on one site might be accessible on another site because sites often share a single world-readable /tmp directory.
