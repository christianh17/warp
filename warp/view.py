# -*- encoding: utf-8 -*-
import flask, smtplib, ssl, email.message, email.utils, time, email.policy

from warp.db import *
from . import utils
from . import blob_storage
from datetime import datetime

bp = flask.Blueprint('view', __name__)

@bp.context_processor
def headerDataInit():

    headerDataL = []

    zoneCursor = Zone.select(Zone.id, Zone.name) \
                     .join(UserToZoneRoles, on=(Zone.id == UserToZoneRoles.zid)) \
                     .where(UserToZoneRoles.login == flask.g.login) \
                     .order_by(Zone.name)

    for z in zoneCursor:
        headerDataL.append(
            {"text": z['name'], "endpoint": "view.zone", "view_args": {"zid":str(z['id'])} })

    if headerDataL:
        headerDataL.insert(0,{"text": "Bookings", "endpoint": "view.bookings", "view_args": {"report":""} })

    headerDataR = [
        {"text": "Report", "endpoint": "view.bookings", "view_args": {"report": "report"} },
        {"text": "Users", "endpoint": "view.users", "view_args": {} },
        {"text": "Groups", "endpoint": "view.groups", "view_args": {} },
        {"text": "Zones", "endpoint": "view.zones", "view_args": {} }
    ]

    #generate urls and selected
    for hdata in [headerDataL,headerDataR]:

        for h in hdata:

            h['url'] = flask.url_for(h['endpoint'],**h['view_args'])
            a = flask.request.endpoint == h['endpoint']
            b = flask.request.view_args == h['view_args']
            h['active'] = flask.request.endpoint == h['endpoint'] and flask.request.view_args == h['view_args']


    return { "headerDataL": headerDataL,
             "headerDataR": headerDataR,
             'hasLogout': 'auth.logout' in flask.current_app.view_functions
    }

#insert ch

def union(self, other_set):
    new_set = [i for i in self.elements]  # which is actually a list
    set_obj = set(new_set)
    for j in other_set:
        if j not in set_obj:
            new_set.append(j)
    return new_set

@bp.route("/blabla")
#@login_required 
def blabla():
    mailContent1 = u"""Hallo, 
 
der folgende Platz ist f\u00fcr Sie am """
    mailContent2 = """ Uhr gebucht.\n\nSollten Sie den gebuchten Platz heute nicht benutzen, stornieren Sie diesen bitte in WARP. F\u00fcr Ver\u00e4nderungen oder Stornierungen nutzen Sie bitte folgenden Link: https://zwarpap001
"""

    mailContent3 = u"""\n\nViele Gr\u00fc\u00dfe"""
    mailSubject1 = "Ihre Buchung am " 
    mailSubject2 = " Uhr - "

    today = datetime.utcnow().date()
    start = datetime(today.year, today.month, today.day)
    startTS = int(datetime.timestamp(start))
    endTS = startTS + 86400
    print (startTS)
    print (endTS)


#https://docs.peewee-orm.com/en/latest/peewee/query_operators.html
    with DB.atomic():
       #c = Book.select(Book.id, Book.login, Book.fromts, Book.tots).where(Book.fromts.between(startTS,endTS)).execute()
       result = (
          Book
         .select(Book.id, Book.login, Book.sid, Book.fromts, Book.tots, Users.mailaddress,Users.name, Seat.name.alias('SeatName'))
         .join (Users, on=(Users.login == Book.login))
         .join (Seat, on=(Seat.id == Book.sid))
         .where((Book.fromts.between(startTS,endTS)&(~(Users.mailaddress.is_null()))))
##         .where((Book.login == 'brennecke03')&(Book.fromts.between(startTS,endTS)&(~(Users.mailaddress.is_null()))))
         .execute()
       )
       resultlist = list(result)
       print ('found users')
       print (resultlist)
       smtp_obj = smtplib.SMTP("smtp.klk-h.de")
       #smtp_obj = smtplib.SMTP("mail.herrmann.es")

       policy = email.policy.compat32.clone(linesep='\n',
          max_line_length=0,
          cte_type='8bit',
          raise_on_defect=True)

# hier weiter machen und UTF-8 in Mails erlauben. Aber: Die Template-Geschichte ist gut.
       for resultline in resultlist:
          # jetzt die Gruppen für den MA ermitteln
          print (resultline)
          groupResult = (
             Groups
            .select(Groups.group)
            .where(Groups.login == resultline["login"])
#            .where(Groups.login == 'brennecke03')
          ) 
          print ('GroupResult:')
          print (groupResult)
          groupResultList = list(groupResult)
          print (groupResultList )
          # alle heute gebuchten Kollegen in aktueller Gruppe heraussuchen
          fullColleagueList = []
#          for aktGroup in groupResultList:
          colleagueResult= (
             Book
            .select(Users.name, Seat.name.alias('SeatName'),Groups.group)
            .join (Users, on=(Users.login == Book.login))
            .join (Seat, on=(Seat.id == Book.sid))
            .join (Groups, on=(Groups.login == Users.login))
#             .where (((Book.fromts.between(startTS,endTS)) & (Groups.group == aktGroup ['theGroup'])))
            .where (Book.fromts.between(startTS,endTS) & (Groups.group.in_(groupResult)))
            .order_by (Seat.name.asc())
            .group_by (Seat.name, Users.name,Groups.group)
#            .execute()
          )
          print (colleagueResult)
          colleagueList = list(colleagueResult)
          mitGebucht = u"\nMit Ihnen sind heute vor Ort anwesend:\n\n"
          lastSeat = ""
          for colleague in colleagueList: 
             if lastSeat != colleague ['SeatName']:
                print (colleague ['name'], ' ' , colleague ['SeatName'], colleague ['group'])
                mitGebucht = mitGebucht + colleague ['SeatName'] + "\t" + colleague ['name'] + '\n'
                lastSeat = colleague ['SeatName']

          msg = email.message.Message(policy)

          msg.add_header('Content-Type', 'text/plain; charset="utf-8"')
          BookDateTS = datetime.fromtimestamp(resultline["fromts"])
          BookDateString = BookDateTS.strftime("%d.%m.%Y um %H:%M")
          SeatNameString = resultline["SeatName"]
          SeatNameString.encode ('utf-8')
          #Ihre Buchung am [DATUM] um [UHRZEIT] - [PLATZNAME]
          msg['Subject'] = mailSubject1 + BookDateString + mailSubject2 + SeatNameString
          msgPayload = mailContent1 + BookDateString + mailContent2 + mitGebucht + mailContent3
          #+ resultline["mailaddress"] +" "+ SeatNameString
          #msgPayload.encode ('utf-8')
          msg.set_payload(msgPayload, charset='utf-8')
          msg['To'] = resultline["mailaddress"]
          msg['From'] = resultline["mailaddress"]
          msg['Bcc'] = "christian.herrmann@krh.de"

#          bcc1 = "christian.herrmann@krh.de"
          #msg['To'] = "christian.herrmann@krh.de"
###          msg['To'] = "Janin.Schnittker@krh.de"
###          smtp_obj.sendmail(msg['From'], [msg['To']], msg.as_string())
          #rcpt =   msg['Bcc'] +', '+ msg['To']
#          rcpt = '<janin.schnittker@krh.de>,<christian.hermann@krh.de>'
#          print (msg)
#          print (rcpt)
          #******************************* an den bcc-Einstellungen muss ich noch schrauben *******************
          smtpresult= smtp_obj.sendmail(msg['From'], [msg['To'], msg['Bcc']] , msg.as_string())
          del msg
#          print (1/0)
          
       smtp_obj.quit()

#    msg = email.message.Message()
#    msg['From'] = "christian.herrmann@krh.de"
#    msg['To'] = "christian.herrmann@krh.de"
#    msg['Subject'] = "E-mail Subject"
#    msg.add_header('Content-Type', 'text')
#    msg.set_payload("This is your message.")

#    smtp_obj = smtplib.SMTP("smtp.klk-h.de")
    #smtp_obj.sendmail(msg['From'], [msg['To']], msg.as_string())


    return flask.render_template('index.html')

# end insert ch


@bp.route("/")
def index():
    return flask.render_template('index.html')

@bp.route("/bookings/<string:report>")
@bp.route("/bookings", defaults={"report": "" })
def bookings(report):

    if report == "report" and not flask.g.isAdmin:
        flask.abort(403)

    return flask.render_template('bookings.html',
        report = (report == "report"),
        maxReportRows = flask.current_app.config['MAX_REPORT_ROWS'])

@bp.route("/zone/<zid>")
def zone(zid):

    zoneRole = UserToZoneRoles.select(UserToZoneRoles.zone_role) \
                              .where( (UserToZoneRoles.zid == zid) & (UserToZoneRoles.login == flask.g.login) ) \
                              .scalar()

    if zoneRole is None:
        flask.abort(403)

    nextWeek = utils.getNextWeek()
    defaultSelectedDates = {
        "slider": [9*3600, 17*3600]
    }

    for d in nextWeek[1:]:
        if not d['isWeekend']:
            defaultSelectedDates['cb'] = [d['timestamp']]
            break

    if zoneRole <= ZONE_ROLE_ADMIN:
        zoneRole = {'isZoneAdmin': True}
    elif zoneRole <= ZONE_ROLE_USER:
        zoneRole = {}
    elif zoneRole <= ZONE_ROLE_VIEWER:
        zoneRole = {'isZoneViewer': True}
    else:
        raise Exception('Undefined role')


    return flask.render_template('zone.html',
        **zoneRole,
        zid = zid,
        nextWeek=nextWeek,
        defaultSelectedDates=defaultSelectedDates)

@bp.route("/zone/image/<zid>")
def zoneImage(zid):

    if not flask.g.isAdmin:

        zoneRole = UserToZoneRoles.select(UserToZoneRoles.zone_role) \
                                .where( (UserToZoneRoles.zid == zid) & (UserToZoneRoles.login == flask.g.login) ) \
                                .scalar()
        if zoneRole is None:
            flask.abort(403)

    blobIdQuery = Zone.select(Zone.iid.alias('id')).where(Zone.id == zid)

    return blob_storage.createBlobResponse(blobIdQuery=blobIdQuery)


@bp.route("/users")
def users():

    if not flask.g.isAdmin:
        flask.abort(403)

    return flask.render_template('users.html')

@bp.route("/groups")
def groups():

    if not flask.g.isAdmin:
        flask.abort(403)

    return flask.render_template('groups.html')

@bp.route("/zones")
def zones():

    if not flask.g.isAdmin:
        flask.abort(403)

    return flask.render_template('zones.html')


@bp.route("/groups/assign/<group_login>")
def groupAssign(group_login):

    if not flask.g.isAdmin:
        flask.abort(403)

    groupName = Users.select(Users.name) \
                     .where( (Users.login == group_login) & (Users.account_type >= ACCOUNT_TYPE_GROUP) ) \
                     .scalar()

    if groupName is None:
        flask.abort(404)

    returnURL = flask.request.args.get('return',flask.url_for('view.groups'))

    return flask.render_template('group_assign.html',
                    groupLogin = group_login,
                    groupName = groupName,
                    returnURL = returnURL)


@bp.route("/zones/assign/<zid>")
def zoneAssign(zid):

    if not flask.g.isAdmin:
        flask.abort(403)

    zoneName = Zone.select(Zone.name) \
                     .where( Zone.id == zid ) \
                     .scalar()

    if zoneName is None:
        flask.abort(404)

    returnURL = flask.request.args.get('return',flask.url_for('view.zones'))

    return flask.render_template('zone_assign.html',
                    zoneName = zoneName,
                    zid = zid,
                    returnURL = returnURL)

@bp.route("/zones/modify/<zid>")
def zoneModify(zid):

    if not flask.g.isAdmin:
        flask.abort(403)

    returnURL = flask.request.args.get('return',flask.url_for('view.zones'))

    return flask.render_template('zone_modify.html',
                    zid = zid,
                    returnURL = returnURL)

