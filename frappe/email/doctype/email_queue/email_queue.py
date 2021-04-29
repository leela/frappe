# -*- coding: utf-8 -*-
# Copyright (c) 2015, Frappe Technologies and contributors
# For license information, please see license.txt

from __future__ import unicode_literals

import json

from rq.timeouts import JobTimeoutException
import smtplib, quopri
from email.parser import Parser

import frappe
from frappe import _, safe_encode
from frappe.model.document import Document
from frappe.email.queue import get_unsubcribed_url
from frappe.email.email_body import add_attachment
from frappe.utils import now_datetime
from email.policy import SMTPUTF8

MAX_RETRY_COUNT = 3
class EmailQueue(Document):
	DOCTYPE = 'Email Queue'

	def set_recipients(self, recipients):
		self.set("recipients", [])
		for r in recipients:
			self.append("recipients", {"recipient":r, "status":"Not Sent"})

	def on_trash(self):
		self.prevent_email_queue_delete()

	def prevent_email_queue_delete(self):
		if frappe.session.user != 'Administrator':
			frappe.throw(_('Only Administrator can delete Email Queue'))

	def get_duplicate(self, recipients):
		values = self.as_dict()
		del values['name']
		duplicate = frappe.get_doc(values)
		duplicate.set_recipients(recipients)
		return duplicate

	@classmethod
	def find(cls, name):
		return frappe.get_doc(cls.DOCTYPE, name)

	def update_db(self, auto_commit=False, **kwargs):
		frappe.db.set_value(self.DOCTYPE, self.name, kwargs)
		if auto_commit:
			frappe.db.commit()

	@property
	def cc(self):
		return self.show_as_cc.split(",")

	@property
	def to(self):
		return [r.recipient for r in self.recipients if r.recipient not in self.cc]

	@property
	def attachments_list(self):
		return json.loads(self.attachments) if self.attachments else []

	# @classmethod
	# def new(cls, doc):
	# 	pass

	def email_account_doc(self):
		if self.email_account: #TODO: Make email account mandatory
			return frappe.get_doc('Email Account', self.email_account)

	def is_sent(self):
		# status Sending ??
		return self.status not in ['Not Sent','Partially Sent']

	def can_send_now(self, force_send=False):
		if frappe.are_emails_muted() or self.is_sent():
			return False

		hold_queue = (cint(frappe.defaults.get_defaults().get("hold_queue"))==1)
		if hold_queue or frappe.flags.in_test:
			return False

		if (not force_send) and self.send_after and self.send_after < now_datetime():
			return False

		return True

	def send(self, force_send=False):
		""" Send emails and respects the send_after attribute.
		Use force_send flag to ignore the send_after.
		"""
		if not self.can_send_now(force_send):
			return

		with SendMailContext(self) as ctx:
			for recipient in self.recipients:
				message = ctx.build_message(recipient)
				ctx.smtp_server.sendmail(recipient.recipient, self.sender, message)
				ctx.add_to_sent_list(recipient.recipient)

class SendMailContext:
	def __init__(self, queue_doc: Document):
		self.queue_doc = queue_doc
		self.email_account_doc = queue_doc.email_account_doc()
		self.smtp_conn = self.email_account_doc.smtp_conn()
		self.sent_to = []

	def __enter__(self):
		self.queue_doc.update_db(status='Sending', auto_commit=True)
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		#TODO: Log error or raise based on request type
		# Close SMTP connection
		# Do rollback?

		exceptions = [
			smtplib.SMTPServerDisconnected,
			smtplib.SMTPAuthenticationError,
			smtplib.SMTPRecipientsRefused,
			smtplib.SMTPConnectError,
			smtplib.SMTPHeloError,
			JobTimeoutException
		]
		if exc_type in exceptions:
			email_status = (self.sent_to and 'Partially Sent') or 'Not Sent'
			self.queue_doc.update_db(status = email_status, auto_commit = True)
			return True

		if exc_type:
			if self.queue_doc.retry < MAX_RETRY_COUNT:
				update_fields = { 'status': 'Not Sent', 'retry': self.queue_doc.retry+1 }
			else:
				update_fields = { 'status': (self.sent_to and 'Partially Errored') or 'Error' }
			self.queue_doc.update_db(**update_fields, auto_commit = True)

	def add_to_sent_list(self, email):
		self.sent_to.append(email)

	def get_message_object(self, message):
		return Parser(policy=SMTPUTF8).parsestr(message)

	def message_placeholder(self, placeholder_key):
		map = {
			'tracker': '<!--email open check-->',
			'unsubscribe_url': '<!--unsubscribe url-->',
			'cc': '<!--cc message-->',
			'recipient': '<!--recipient-->',
		}
		return map.get(placeholder_key)

	def build_message(self, recipient):
		"""Build message specific to the recipient.
		"""
		message = self.queue_doc.message
		message = message.replace(self.message_placeholder('tracker'), self.get_tracker_str())
		message = message.replace(self.message_placeholder('unsubscribe_url'),
			self.get_unsubscribe_str(recipient.recipient))
		message = message.replace(self.message_placeholder('cc'), self.get_receivers_str())
		message = message.replace(self.message_placeholder('recipient'),
			self.get_receipient_str(recipient.recipient))
		message = self.include_attachments(message)
		return message

	def get_tracker_str(self):
		tracker_url_html = \
			'<img src="https://{}/api/method/frappe.core.doctype.communication.email.mark_email_as_seen?name={}"/>'

		message = ''
		if frappe.conf.use_ssl and self.queue_doc.track_email_status:
			message = quopri.encodestring(
				tracker_url_html.format(frappe.local.site, self.queue_doc.communication).encode()
			).decode()
		return message

	def get_unsubscribe_str(self, recipient_email):
		unsubscribe_url = ''
		if self.queue_doc.add_unsubscribe_link and self.queue_doc.reference_doctype:
			doctype, doc_name = self.queue_doc.reference_doctype, self.queue_doc.reference_name
			unsubscribe_url = get_unsubcribed_url(doctype, doc_name, recipient_email,
				self.queue_doc.unsubscribe_method, self.queue_doc.unsubscribe_param)

		return quopri.encodestring(unsubscribe_url.encode()).decode()

	def get_receivers_str(self):
		message = ''
		if self.queue_doc.expose_recipients == "footer":
			to_str =  ', '.join(self.queue_doc.to)
			cc_str = ', '.join(self.queue_doc.cc)
			message = f"This email was sent to {to_str}"
			message = message + f" and copied to {cc_str}" if cc_str else message
		return message

	def get_receipient_str(self, recipient_email):
		message = ''
		if self.queue_doc.expose_recipients != "header":
			message = recipient_email
		return message

	def include_attachments(self, message):
		# TODO: understand and clean
		message_obj = self.get_message_object(message)
		attachments = self.queue_doc.attachments_list

		for attachment in attachments:
			if attachment.get('fcontent'): continue

			fid = attachment.get("fid")
			if fid:
				_file = frappe.get_doc("File", fid)
				fcontent = _file.get_content()
				attachment.update({
					'fname': _file.file_name,
					'fcontent': fcontent,
					'parent': message_obj
				})
				attachment.pop("fid", None)
				add_attachment(**attachment)

			elif attachment.get("print_format_attachment") == 1:
				attachment.pop("print_format_attachment", None)
				print_format_file = frappe.attach_print(**attachment)
				print_format_file.update({"parent": message_obj})
				add_attachment(**print_format_file)

		return safe_encode(message_obj.as_string())

@frappe.whitelist()
def retry_sending(name):
	doc = frappe.get_doc("Email Queue", name)
	if doc and (doc.status == "Error" or doc.status == "Partially Errored"):
		doc.status = "Not Sent"
		for d in doc.recipients:
			if d.status != 'Sent':
				d.status = 'Not Sent'
		doc.save(ignore_permissions=True)

@frappe.whitelist()
def send_now(name):
	record = EmailQueue.find(name)
	if record:
		record.send(force_send = True)

def on_doctype_update():
	"""Add index in `tabCommunication` for `(reference_doctype, reference_name)`"""
	frappe.db.add_index('Email Queue', ('status', 'send_after', 'priority', 'creation'), 'index_bulk_flush')
