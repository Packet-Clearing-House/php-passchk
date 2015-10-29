# php-passchk

php-passchk is a semi-faithful port of Tyler Akins's [passchk.js](http://rumkin.com/tools/password/passchk.php). The main impetus to write this was to have a way to generate the entropy server side from a password.  You can then use this measurement to safely set a password expire date with out needing to trust the value from an HTML form value populated from a client side JS call.

To this end, the class not only returns `bits` in entropy and `length`, but also `time_to_crack`, `valid` and `days`.

Finally, it also returns the `simple_to_bits` value based on simple entropy calculate of `entropy = n * lg(c)` which is mentioned in DropBox's great post on [password strength calculation](https://blogs.dropbox.com/tech/2012/04/zxcvbn-realistic-password-strength-estimation/).

To us this library, include it, instantiate it and call `ShowStats()`:

~~~
require_once(passchk.php);
$passStats = new passchk();
$passAry = $passStats->ShowStats('correct horse battery staple');
print_r($passAry);
~~~

This code will output:

~~~
Array
(
    [length] => 28
    [time_to_crack] => 86 years
    [valid] => 86 years
    [days] => 31566
    [simple_bits] => 92.28
    [bits] => 108.64
)
~~~

This code is released under the [GPLv3](https://blogs.dropbox.com/tech/2012/04/zxcvbn-realistic-password-strength-estimation/) license. 

If you see something wrong, please open an issue.  If you see something wrong and have time to spare, please open an issue and submit a pull request!