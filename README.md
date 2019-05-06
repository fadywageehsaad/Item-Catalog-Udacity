# Udacity Item-Catalog Full-stack nanodegree project
Create a restaurant menu app where users can add, edit, and delete restaurants and menu items in the restaurants.
## Setup 
### Prerequisites
#### Python 2.7
##### Install Python 
###### Windows
for more information on installing python on windows machine please see this site: [Windows Install](https://www.ics.uci.edu/~pattis/common/handouts/pythoneclipsejava/python.html)

##### Linux
for more information on installing python on linux machine please see this site: [linux Install](https://docs.aws.amazon.com/cli/latest/userguide/install-linux-python.html)

##### OSX 
for more information on installing python on linux machine please see this site: [OSX Install](https://docs.python-guide.org/starting/install3/osx)

#### Vagrant
##### Install Vagrant 
###### All OS types
for more information on installing Vagrant on windows machine please see this site: [Install Vagrant](https://www.vagrantup.com/docs/installation)

#### VirtualBox
##### Install VirtualBox
###### Windows
for more information on installing VirtualBox on windows machine please see this site: [Windows Install](https://websiteforstudents.com/installing-virtualbox-windows-10/)

##### Linux
for more information on installing VirtualBox on linux machine please see this site: [linux Install](https://websiteforstudents.com/installing-virtualbox-5-2-ubuntu-17-04-17-10/)

##### OSX 
for more information on installing VirtualBox on linux machine please see this site: [OSX Install](https://matthewpalmer.net/blog/2017/12/10/install-virtualbox-mac-high-sierra/index.html)


### How to Run
1. Clone this repo
2. Unzip and place the Item Catalog folder in your Vagrant directory
3. Launch Vagrant
```
$ Vagrant up 
```
4. Login to Vagrant
```
$ Vagrant ssh
```
5. Change directory to `/vagrant`
```
$ Cd /vagrant
```
6. Initialize the database
```
$ Python database-setup.py
```
7. Launch application
```
$ Python catalog.py
```
8. Open the browser and go to http://localhost:5000
9. Enjoy
