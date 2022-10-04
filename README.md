
# Partner Notification

Partner Notification processes focus on the notification of sexual partners to prevent the transmission of Sexually Transmitted Infections (STIs). The INTEGRATE Joint Action provides an integrated platform called RiskRadar, for combination prevention activities targeting STIs, including an anonymous, free and voluntary Partner Notification service. The presented service information flow ensures privacy, security and GDPR compliance which were identified as vital with similar tools. The service is available via web and mobile interfaces using a unique random code provided from authorised healthcare professionals to support privacy.


## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

- What things you need to install on your system


```
* Python 3.x.x

* You can install the requirement packages found in the pn_requirements.txt file via pip (although depending on your system configuration and setup, e.g. database engine, python version etc. you might need to change package versions, or add some extra packages): _pip install -r pn_requirements.txt_
```
- An SMS messaging service with its relevant API is required.

## Deployment

Adjust settings in the config.py file to your own system settings.

* Just run app.py in the local directory with python3 on your local machine **for development and testing purposes**.
* To deploy the project **on a live system**, follow the instruction given by the official documentation of flask on http://flask.pocoo.org/docs/0.12/deploying/

## Built With

* [Python 3.6.1](http://www.python.org/) - Developing with the best programming language
* [Flask 1.1.1](http://flask.pocoo.org/) - Flask web development, one drop at a time

## Authors

* **Vlasios Dimitriadis** - *Initial work* - [partner-notification](https://github.com/bdimitriadis/partner-notification)
