# github-jira-sync
Copy github issues to JIRA tickets and close JIRA tickets when github issues are closed.

This is for use when *github* is the source of truth for your tickets and you are copying to JIRA
to keep another team in sync.

This will *not* read JIRA tickets and copy them to github issues.

Most of this code unabashedly stolen from: https://github.com/IQAndreas/github-issues-import
And this uses the python JIRA module: https://github.com/pycontribs/jira

This will create a label on each github issue to keep track of the related JIRA issue number.  The github label will have a "jira:" prefix 
to identify it.  If you already use labels on your github issues that start with "jira:" for some reason this sync probably won't work for you.

The first time this runs it will create issues in JIRA for each issue in github based on the issue type filter you provide.  Each
JIRA ticket created will be labeled into the github issue.  The create JIRA ticket will have a link to the github issue and copy the
summary and description fields into JIRA.  Future syncs will only compare the state of the github issue with the state of the JIRA ticket
copying state from github -> JIRA and obeying the state mapping you have configured in your config. 

You can run this sync from a script on a crontab or something with a script like:

```
#!/bin/bash

# The absolute, canonical ( no ".." ) path to this script
DIR=$(cd -P -- "$(dirname -- "$0")" && printf '%s\n' "$(pwd -P)")
pushd $DIR > /dev/null

declare -a repos=("myorg/myrepo1"
                  "myorg/myrepo1"
                  "otherorg/otherrepo1"
                 )

for i in "${repos[@]}"
do
    ./sync.py -u github_user -p <api_pass_hash> -s ${i} --all -t <JIRA project> -j https://myorg.atlassian.net -U <jira account> -P <jira_pass_hash>
done

popd > /dev/null
```
