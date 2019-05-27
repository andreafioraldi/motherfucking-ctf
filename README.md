# MotherFucking CTF
What do we say to JavaScript? Not today! [motherfuckingwebsite.com](https://motherfuckingwebsite.com/) inspired CTF platform.

Demo [here](https://motherfucking-ctf-demo.herokuapp.com/).

## Why?

Are you tired of complex websites with useless heavy features and you want host
a CTF for your leet hackers friends?

CTFd is too heavy for the free dyno on Heroku?

Are You a fan of [motherfuckingwebsite.com](https://motherfuckingwebsite.com/) like me?

Well, this is the rigth CTF plaform for you.

## Overview

Define a description of the CTF in templates/index.html.

Define the set of challenges in chals.py.

Run `python chals.py` to setup the database.

Run `python run.py` and you are up.

On Heroku you should only enable the Heroku Postgres extension.

## Score policy

I don't like the CTFs that benefit players depending on the timezone, so there
isn't first blood.

All the challenges starts with the same points. More solves, less points.
This choice let the users to define the difficulty of a challenge.

If two players have the same score the rank is computed looking at the last
submission time.

## Whoami

I'm malweisse and I play with TRX and mhackeroni.

[Twitter](https://twitter.com/andreafioraldi)
