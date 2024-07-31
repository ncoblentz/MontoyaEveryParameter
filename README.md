# Every Parameter Burp Extension

_By [Nick Coblentz](https://www.linkedin.com/in/ncoblentz/)_

__This Burp Extension is made possible by [Virtue Security](https://www.virtuesecurity.com), the Application Penetration Testing consulting company I work for.__

## About

The __Every Parameter Extension__ allows you to choose a set of payloads from a context menu and then it iterates through every header and parameter value in the request and sends that payload. The results should be reviewed manually from the logger tab. Use Bambda's to filter out things you know for sure you aren't interested in.

## How to Use It

- Build it with `gradlew shadowJar`
- Add the extension in burp from the `build/libs/MontoyaEveryParameter-x.y.z-all.jar` folder where `x.y.z` represents the build version