#!/usr/bin/env python3

import urllib.request, urllib.error, urllib.parse
import json
import base64
import sys, os
import datetime
import argparse, configparser
from jira import JIRA
import re

import query

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
default_config_file = os.path.join(__location__, 'config.ini')
config = configparser.RawConfigParser()

class state:
	current = ""
	INITIALIZING		 = "script-initializing"
	LOADING_CONFIG		 = "loading-config"
	FETCHING_ISSUES		 = "fetching-issues"
	GENERATING			 = "generating"
	IMPORT_CONFIRMATION	 = "import-confirmation"
	IMPORTING			 = "importing"
	IMPORT_COMPLETE		 = "import-complete"
	COMPLETE			 = "script-complete"

state.current = state.INITIALIZING

http_error_messages = {}
http_error_messages[401] = "ERROR: There was a problem during authentication.\nDouble check that your username and password are correct, and that you have permission to read from or write to the specified repositories."
http_error_messages[403] = http_error_messages[401]; # Basically the same problem. GitHub returns 403 instead to prevent abuse.
http_error_messages[404] = "ERROR: Unable to find the specified repository.\nDouble check the spelling for the source and target repositories. If either repository is private, make sure the specified user is allowed access to it."

def init_config():

	config.add_section('login')
	config.add_section('source')
	config.add_section('jira')
	config.add_section('format')
	config.add_section('settings')

	arg_parser = argparse.ArgumentParser(description="Import issues from a GitHub repository into a single JIRA project.")

	config_group = arg_parser.add_mutually_exclusive_group(required=False)
	config_group.add_argument('--config', help="The location of the config file (either absolute, or relative to the current working directory). Defaults to `config.ini` found in the same folder as this script.")
	config_group.add_argument('--no-config', dest='no_config',	action='store_true', help="No config file will be used, and the default `config.ini` will be ignored. Instead, all settings are either passed as arguments, or (where possible) requested from the user as a prompt.")

	arg_parser.add_argument('-u', '--username', help="The username of the account that will read the Github issues. The username will not be stored anywhere if passed in as an argument.")
	arg_parser.add_argument('-p', '--password', help="The password (in plaintext) of the account that will read the Github issues. The password will not be stored anywhere if passed in as an argument.")
	arg_parser.add_argument('-s', '--source', help="The source repository which the issues should be copied from. Should be in the format `user/repository`.")
	arg_parser.add_argument('-t', '--project', help="The destination JIRA project name where issues should be put.")
	arg_parser.add_argument('-j', '--jira', help="The JIRA server to connect to.")
	arg_parser.add_argument('-U', '--jira-user', dest='jira_user', help="The destination JIRA project name where issues should be put.")
	arg_parser.add_argument('-P', '--jira-pass', dest='jira_pass', help="The JIRA server to connect to.")
	arg_parser.add_argument('-T', '--jira-default-type', dest='default_type', help="The JIRA default type for new issues, if the bug,enhancement labels are not present on the github issue")

	arg_parser.add_argument('--ignore-comments',  dest='ignore_comments',  action='store_true', help="Do not import comments into JIRA")
	arg_parser.add_argument('--ignore-labels',	  dest='ignore_labels',	   action='store_true', help="Do not import labels attached to the issue.")

	arg_parser.add_argument('--issue-template', help="Specify a template file for use with issues.")
	arg_parser.add_argument('--comment-template', help="Specify a template file for use with comments.")

	include_group = arg_parser.add_mutually_exclusive_group(required=True)
	include_group.add_argument("--all", dest='import_all', action='store_true', help="Import all issues, regardless of state.")
	include_group.add_argument("--open", dest='import_open', action='store_true', help="Import only open issues.")
	include_group.add_argument("--closed", dest='import_closed', action='store_true', help="Import only closed issues.")
	include_group.add_argument("-i", "--issues", type=int, nargs='+', help="The list of issues to import.");

	args = arg_parser.parse_args()

	def load_config_file(config_file_name):
		try:
			config_file = open(config_file_name)
			config.read_file(config_file)
			return True
		except (FileNotFoundError, IOError):
			return False

	if args.no_config:
		print("Ignoring default config file. You may be prompted for some missing settings.")
	elif args.config:
		config_file_name = args.config
		if load_config_file(config_file_name):
			print("Loaded config options from '%s'" % config_file_name)
		else:
			sys.exit("ERROR: Unable to find or open config file '%s'" % config_file_name)
	else:
		config_file_name = default_config_file
		if load_config_file(config_file_name):
			print("Loaded options from default config file in '%s'" % config_file_name)
		else:
			print("Default config file not found in '%s'" % config_file_name)
			print("You may be prompted for some missing settings.")


	if args.username: config.set('login', 'username', args.username)
	if args.password: config.set('login', 'password', args.password)

	if args.source: config.set('source', 'repository', args.source)
	if args.jira: config.set('jira', 'repository', args.project)
	if args.jira: config.set('jira', 'server', args.jira)
	if args.jira_user: config.set('jira', 'username', args.jira_user)
	if args.jira_pass: config.set('jira', 'password', args.jira_pass)
	if args.default_type: config.set('jira', 'default_type', args.default_type)


	if args.issue_template: config.set('format', 'issue_template', args.issue_template)
	if args.comment_template: config.set('format', 'comment_template', args.comment_template)

	config.set('settings', 'import-comments',  str(not args.ignore_comments))
	config.set('settings', 'import-labels',	   str(not args.ignore_labels))

	config.set('settings', 'import-open-issues',   str(args.import_all or args.import_open));
	config.set('settings', 'import-closed-issues', str(args.import_all or args.import_closed));


	# Make sure no required config values are missing
	if not config.has_option('source', 'repository') :
		sys.exit("ERROR: There is no source repository specified either in the config file, or as an argument.")
	if not config.has_option('jira', 'repository') :
		sys.exit("ERROR: There is no target jira project specified either in the config file, or as an argument.")
	if not config.has_option('jira', 'server') :
		sys.exit("ERROR: There is no target jira server specified either in the config file, or as an argument.")
	if not config.has_option('jira', 'default_type') :
		config.set('jira', 'default_type', 'Bug')

	def get_server_for(which):
		# Default to 'github.com' if no server is specified
		if (not config.has_option(which, 'server')):
			config.set(which, 'server', "github.com")

		# if SOURCE server is not github.com, then assume ENTERPRISE github (yourdomain.com/api/v3...)
		if (config.get(which, 'server') == "github.com") :
			api_url = "https://api.github.com"
		else:
			api_url = "https://%s/api/v3" % config.get(which, 'server')

		config.set(which, 'url', "%s/repos/%s" % (api_url, config.get(which, 'repository')))

	get_server_for('source')

	# Prompt for username/password if none is provided in either the config or an argument
	def get_credentials_for(which):
		if not config.has_option(which, 'username'):
			if config.has_option('login', 'username'):
				config.set(which, 'username', config.get('login', 'username'))
			elif ( (which == 'target') and query.yes_no("Do you wish to use the same credentials for the target repository?") ):
				config.set('target', 'username', config.get('source', 'username'))
			else:
				query_str = "Enter your username for '%s' at '%s': " % (config.get(which, 'repository'), config.get(which, 'server'))
				config.set(which, 'username', query.username(query_str))

		if not config.has_option(which, 'password'):
			if config.has_option('login', 'password'):
				config.set(which, 'password', config.get('login', 'password'))
			elif ( (which == 'target') and config.get('source', 'username') == config.get('target', 'username') and config.get('source', 'server') == config.get('target', 'server') ):
				config.set('target', 'password', config.get('source', 'password'))
			else:
				query_str = "Enter your password for '%s' at '%s': " % (config.get(which, 'repository'), config.get(which, 'server'))
				config.set(which, 'password', query.password(query_str))

	get_credentials_for('source')
	get_credentials_for('jira')

	# Everything is here! Continue on our merry way...
	return args.issues or []

def format_date(datestring):
	# The date comes from the API in ISO-8601 format
	date = datetime.datetime.strptime(datestring, "%Y-%m-%dT%H:%M:%SZ")
	date_format = config.get('format', 'date', fallback='%A %b %d, %Y at %H:%M GMT', raw=True);
	return date.strftime(date_format)

def format_from_template(template_filename, template_data):
	from string import Template
	template_file = open(template_filename, 'r')
	template = Template(template_file.read())
	return template.substitute(template_data)

def format_issue(template_data):
	default_template = os.path.join(__location__, 'templates', 'issue.md')
	template = config.get('format', 'issue_template', fallback=default_template)
	return format_from_template(template, template_data)

def format_pull_request(template_data):
	default_template = os.path.join(__location__, 'templates', 'pull_request.md')
	template = config.get('format', 'pull_request_template', fallback=default_template)
	return format_from_template(template, template_data)

def format_comment(template_data):
	default_template = os.path.join(__location__, 'templates', 'comment.md')
	template = config.get('format', 'comment_template', fallback=default_template)
	return format_from_template(template, template_data)


def send_request(which, url, post_data=None, verb="GET"):

	if post_data is not None:
		post_data = json.dumps(post_data).encode("utf-8")

	full_url = "%s/%s" % (config.get(which, 'url'), url)
	req = urllib.request.Request(full_url, data=post_data, method=verb)

	username = config.get(which, 'username')
	password = config.get(which, 'password')
	req.add_header("Authorization", b"Basic " + base64.urlsafe_b64encode(username.encode("utf-8") + b":" + password.encode("utf-8")))

	req.add_header("Content-Type", "application/json")
	req.add_header("Accept", "application/json")
	req.add_header("User-Agent", "rileyberton/github-jira-sync")

	try:
		response = urllib.request.urlopen(req)
		json_data = response.read()
	except urllib.error.HTTPError as error:

		error_details = error.read();
		error_details = json.loads(error_details.decode("utf-8"))

		if error.code in http_error_messages:
			sys.exit(http_error_messages[error.code])
		else:
			error_message = "ERROR: There was a problem importing the issues.\n%s %s" % (error.code, error.reason)
			if 'message' in error_details:
				error_message += "\nDETAILS: " + error_details['message']
			sys.exit(error_message)

	return json.loads(json_data.decode("utf-8"))


def get_labels(which):
	return send_request(which, "labels")

def get_issue_by_id(which, issue_id):
	return send_request(which, "issues/%d" % issue_id)

def get_issues_by_id(which, issue_ids):
	# Populate issues based on issue IDs
	issues = []
	for issue_id in issue_ids:
		issues.append(get_issue_by_id(which, int(issue_id)))

	return issues

# Allowed values for state are 'open' and 'closed'
def get_issues_by_state(which, state):
	issues = []
	page = 1
	while True:
		new_issues = send_request(which, "issues?state=%s&direction=asc&page=%d" % (state, page))
		if not new_issues:
			break
		for issue in new_issues:
			if not "pull_request" in issue or issue['pull_request']['html_url'] is None:
				issues.append(issue)
		page += 1
	return issues

def get_comments_on_issue(which, issue):
	if issue['comments'] != 0:
		return send_request(which, "issues/%s/comments" % issue['number'])
	else :
		return []

def sync_state(issue, tkt, jira):
	if 'closed_at' in issue and issue['closed_at'] and tkt.fields.resolution is None:
		transitions = jira.transitions(tkt)
		close_id = ''
		for t in transitions:
			if t['name'] == 'Done':
				close_id = t['id']
				break
			if t['name'] == 'Closed':
				close_id = t['id']
				break
		print(" > GH issue is closed, transition jira to state id %s\n" % close_id)
		tkt.update(summary=issue['title'])
		jira.transition_issue(tkt, close_id)
	elif 'closed_at' not in issue and tkt.fields.resolution is not None:
		transitions = jira.transitions(tkt)
		open_id = ''
		for t in transitions:
			if t['name'] == 'Backlog':
				open_id = t['id']
				break
		print(" > GH issue is open, transition jira to state id %s\n" % open_id)
		tkt.update(summary=issue['title'])
		jira.transition_issue(tkt, open_id)

# Will only import issues that are in use by the imported issues, and do not exist in JIRA
def sync_issues(issues):

	state.current = state.GENERATING

	def get_label_by_name(name):
		for label in known_labels:
			if label['name'] == name : return label
		return None

	new_issues = []
	num_new_comments = 0
	new_milestones = []

	# login to jira
	username = config.get('jira', 'username')
	password = config.get('jira', 'password')
	server = config.get('jira', 'server')

	auth_jira = JIRA(server, basic_auth=(username, password))
	if not auth_jira:
		error_message = "ERROR: There was a problem logging into jira.	Please check jira credentials.\n"
		sys.exit(error_message)


	for issue in issues:

		new_issue = {}
		new_issue['title'] = issue['title']
		new_issue['number'] = issue['number']
		new_issue['url'] = issue['html_url']
		new_issue['labels'] = []

		# Temporary fix for marking closed issues
		if issue['closed_at']:
			new_issue['title'] = "[CLOSED] " + new_issue['title']
			new_issue['closed_at'] = issue['closed_at']

		if config.getboolean('settings', 'import-comments') and 'comments' in issue and issue['comments'] != 0:
			num_new_comments += int(issue['comments'])
			new_issue['comments'] = get_comments_on_issue('source', issue)

		if config.getboolean('settings', 'import-labels') and 'labels' in issue and issue['labels'] is not None:
			for issue_label in issue['labels']:
				new_issue['labels'].append(issue_label['name'])

		template_data = {}
		template_data['user_name'] = issue['user']['login']
		template_data['user_url'] = issue['user']['html_url']
		template_data['user_avatar'] = issue['user']['avatar_url']
		template_data['date'] = format_date(issue['created_at'])
		template_data['url'] =	issue['html_url']
		template_data['body'] = issue['body']

		if "pull_request" in issue and issue['pull_request']['html_url'] is not None:
			new_issue['body'] = format_pull_request(template_data)
		else:
			new_issue['body'] = format_issue(template_data)

		new_issues.append(new_issue)

	state.current = state.IMPORT_CONFIRMATION

	print("You are about to sync to '" + config.get('jira', 'server') + "':")
	print(" *", len(new_issues), "issues")
	print(" *", num_new_comments, "comments")
	# if not query.yes_no("Are you sure you wish to continue?"):
	# 	sys.exit()

	state.current = state.IMPORTING

	result_issues = []
	for issue in new_issues:

		# if the issue does not have a matching JIRA ticket, add it
		tkts = auth_jira.search_issues('GithubIssue ~ "%s"' % (issue['url']))
		if tkts is not None and len(tkts) > 0:
			# this issue is already linked to JIRA.. do the needful on state
			tkt = tkts[0]
			if tkt:
				print(" > GH Issue: '%s' already in JIRA %s\n" % (issue['title'], str(tkt.key)))
				sync_state(issue, tkt, auth_jira)
			else:
				print(" > Cannot locate %s in JIRA, something amiss" % (issue['url']))
				sys.exit()

		else:
			# issue is not in jira, create it
			issue_type = config.get('jira', 'default_type')
			if 'bug' in issue['labels']:
				issue_type = 'Bug'
			elif 'enhancement' in issue['labels']:
				issue_type = 'Improvement'

			# if not query.yes_no("About to create JIRA issue from GH issue: %d, continue?" % issue['number']):
			# 	sys.exit()

			external_id = "%s" % (issue['url'])
			tkt = auth_jira.create_issue(fields={
											 u'customfield_10100': external_id,
											 u'project': config.get('jira', 'repository'),
											 u'summary': issue['title'],
											 u'description': issue['body'],
											 u'issuetype': {'name': issue_type}})
			if not tkt:
				print("Error creating JIRA ticket")
				sys.exit()
			else:
				print('Created %s\n' % str(tkt.key))


	state.current = state.IMPORT_COMPLETE


if __name__ == '__main__':

	state.current = state.LOADING_CONFIG

	issue_ids = init_config()
	issues = []

	state.current = state.FETCHING_ISSUES

	# Argparser will prevent us from getting both issue ids and specifying issue state, so no duplicates will be added
	if (len(issue_ids) > 0):
		issues += get_issues_by_id('source', issue_ids)

	if config.getboolean('settings', 'import-open-issues'):
		issues += get_issues_by_state('source', 'open')

	if config.getboolean('settings', 'import-closed-issues'):
		issues += get_issues_by_state('source', 'closed')

	# Sort issues based on their original `id` field
	# Confusing, but taken from http://stackoverflow.com/a/2878123/617937
	issues.sort(key=lambda x:x['number'])

	# Further states defined within the function
	# Finally, add these issues to JIRA
	sync_issues(issues)

	state.current = state.COMPLETE
