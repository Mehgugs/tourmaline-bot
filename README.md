[discordia]: https://github.com/SinisterRectus/Discordia
[framework]: https://github.com/Mehgugs/tourmaline-framework
# tourmaline-bot
A discord bot to test [my framework][framework], and provide some miscellaneous utilities.

>This repository is mainly for helping others understand some of the more complex tasks in luvit, I don't claim this code is anything other than passable (mostly)

### If for some reason you'd want to host a version of this bot (why?)

#### Setup and things you'd need to add

- `git clone https://github.com/SinisterRectus/Discordia.wiki.git` and copy the classes folder into `plugins/public/discordia-docs`.
- If you want that stupid token command to work you'll need to add an API key to your github user or use one from an OAuth2 application and place it in `.config:github-token`.
- You'll need to add a `TOKEN` file to the working directory (same level as main.lua) or configure the callback to T() to provide a token.
- You'll need to have a rethinkdb instance running, I included setup for a barebones out-of-the-box client login.
- I recommend managing this app with `pm2` or equiv. 
- Install [Discordia][discordia]
- Install the [framework] by cloning the repo and copying the `framework` folder to your deps.
- At the time of writing luvit-reql does not support concurrent reads so I used [truemedian's fork](https://github.com/truemedian/luvit-reql)

### A bit about the framework

The framework provides a command interface to make creation of "bot commands" a bit easier (in theory); a plugin system for modular hot reloading which comes with it's own require system 
and various utilities like a (poorly written) embed builder. It's also quite easy to extend / hack and some of that is employed to do some fancy stuff.
