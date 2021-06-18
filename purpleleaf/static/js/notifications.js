$(document).ready(function(){
    function GetNotifications(){
        $.ajax({
            type: "GET",
            url: "/api/notifications",

        success: function(response) {
            if (response.status && response.status_code == '200'){
                var total_notifications = response.notification_list.length;
                var notification_text = ''
                var link = ''
                $('#notification-ul').removeClass('hidden');
                $('#notification-icon').text(total_notifications);
                $('#notification-icon').addClass('info-label blue-bg');
                $('#notification-ul').html('');
                if (total_notifications > 1){
                    notifications_status = "<li class='dropdown-header' id='notifications-status'>You have "+ total_notifications +" new notifications</li>"
                }
                else{
                    notifications_status = "<li class='dropdown-header' id='notifications-status'>You have "+ total_notifications +" new notification</li>"
                }
                var notifications_status2 = "<span class='notify_all'><a href='/notifications'>See all notifications </a></span>"

                $('#notification-ul').append(notifications_status);
                $.each(response.notification_list, function (i, item){
                    if (item.status == "Closed"){
                        if (item.count > 1){
                            notification_text = item.count + " instances of "+ item.issue +" were closed"
                        }
                        else{
                            notification_text = item.count + " instance of "+ item.issue +" was closed"
                        }
                        link = "<a href='/history' onclick=\"UpdateNotification('" + item.issue + "')\" value='"+ item.issue +"' class=''>" + notification_text + "</a>"
                        html_content = "<li><div class='details' id='notification-div'>"+ link + "</div></li>"
                        $('#notification-ul').append(html_content);
                    }
                    else if (item.status == "Leave_Open"){
                        if (item.count > 1){
                            notification_text = item.count + " instances of "+ item.issue +" have been retested but the finding is still open."
                            }
                            else{
                                notification_text = item.count + " instance of "+ item.issue +" has been retested but the finding is still open."
                            }
                            link = "<a href='/vulnerabilities/"+ item.network_type + "/" + item.virtue_id +"/' onclick=\"UpdateNotification('" + item.issue + "')\" value='"+ item.issue +"' class=''>" + notification_text + "</a>"
                            html_content = "<li><div class='details' id='notification-div'>"+ link + "</div></li>"
                            $('#notification-ul').append(html_content);
                
                        }
                });
            
                $('#notification-ul').append(notifications_status2);
            }
            else if (response.status_code == '200' && !response.status){
                $('#notification-ul').html('');
                var notifications_status = "<li class='dropdown-header' id='notifications-status'>You do not have any new notification</li>"
                var notifications_status2 = "<span class='notify_all'><a href='/notifications'>See all notifications </a></span>"
                // $('#notification-ul').addClass('hidden');
                $('#notification-ul').append(notifications_status);
                $('#notification-ul').append(notifications_status2);
            }
            else{
                $('#notification-ul').html('');
                var notifications_status = "<li class='dropdown-header' id='notifications-status'>You do not have any new notification</li>"
                var notifications_status2 = "<span class='notify_all'><a href='/notifications'>See all notifications </a></span>"
                // $('#notification-ul').addClass('hidden');
                $('#notification-ul').append(notifications_status);
                $('#notification-ul').append(notifications_status2);
            }
        },
        error: function(XMLHttpRequest, textStatus, errorThrown)
        {
            $('#notification-ul').html('');
            $('#notification-ul').addClass('hidden');
        }

        });
    }
    GetNotifications();
    var set_notification_interval_obj;
    function PushNotifications(){
        set_notification_interval_obj = setInterval(GetNotifications, 15000);
    }
    function stop_notification_interval()
    {
        clearInterval(set_notification_interval_obj);
    }
    function HoldNotify(){
        setTimeout(PushNotifications, 30000);
    }
    HoldNotify();
    setTimeout(function(){
        $('#error-alert').fadeOut();}, 6000);
});


function UpdateNotification(titleObj){
        $.ajax({
            type: "GET",
            data: {
            'title': titleObj
            },
            url: "/update-notifications",
        });
    };