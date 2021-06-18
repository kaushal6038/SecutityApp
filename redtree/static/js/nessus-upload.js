$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        function getCookie(name) {
            var cookieValue = null;
            if (document.cookie && document.cookie != '') {
                var cookies = document.cookie.split(';');
                for (var i = 0; i < cookies.length; i++) {
                    var cookie = jQuery.trim(cookies[i]);
                    // Does this cookie string begin with the name we want?
                    if (cookie.substring(0, name.length + 1) == (name + '=')) {
                        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                        break;
                    }
                }
            }
            return cookieValue;
        }
        if (!(/^http:./.test(settings.url) || /^https:./.test(settings.url))) {
            // Only send the token to relative URLs i.e. locally.
            xhr.setRequestHeader("X-CSRFToken", getCookie('csrftoken'));
        }
    }
});


var nessus_set_interval_obj;

function set_nessus_get_status_time_interval()
{
    nessus_set_interval_obj = setInterval(create_nessus_file_table, 5000);
}

function get_risk_button(risk, risk_value){

    if (risk_value){
        risk_btn = '<button class="btn btn-'+ risk +'-count btn-xs">'
        risk_btn += risk_value
        risk_btn += '</button>&nbsp;'
    }
    else{
        risk_btn = '<button class="btn btn-'+ risk +'-count btn-xs">'
        risk_btn += 0
        risk_btn += '</button>&nbsp;'
    }
    return risk_btn
}


function get_progress_bar(xml_status, app_status, vul_status, comp_status){
    
    var main_bar = '<div class="progress no-margin">'
    var success_bar = '<div class="progress-bar progress-bar-success" style="width: 33.33%"></div>'
    var danger_bar = '<div class="progress-bar progress-bar-danger" style="width: 33.33%"></div>'
    if (comp_status){
        if (xml_status && app_status && vul_status){
            main_bar += success_bar
            main_bar += success_bar
            main_bar += success_bar
        }
        else if(xml_status && app_status && !vul_status){
            main_bar += success_bar
            main_bar += success_bar
            main_bar += danger_bar
        }
        else if (xml_status && vul_status && !app_status){
            main_bar += success_bar
            main_bar += danger_bar
            main_bar += success_bar
        }
        else if (vul_status && app_status && !xml_status){
            main_bar += danger_bar
            main_bar += success_bar
            main_bar += success_bar
        }
        else if (xml_status && !app_status && !vul_status){
            main_bar += success_bar
            main_bar += danger_bar
            main_bar += danger_bar
        }
        else if (app_status && !xml_status && !vul_status){
            main_bar += danger_bar
            main_bar += success_bar
            main_bar += danger_bar
        }
        else if (vul_status && !app_status && !xml_status){
            main_bar += danger_bar
            main_bar += danger_bar
            main_bar += success_bar
        }
        else{
            main_bar += danger_bar
            main_bar += danger_bar
            main_bar += danger_bar
        }
    }
    else {
        if (xml_status && app_status && vul_status){
            main_bar += success_bar
            main_bar += success_bar
            main_bar += success_bar
        }
        else if(xml_status && app_status && !vul_status){
            main_bar += success_bar
            main_bar += success_bar
        }
        else if (xml_status && vul_status && !app_status){
            main_bar += success_bar
            main_bar += success_bar
        }
        else if (vul_status && app_status && !xml_status){
            main_bar += success_bar
            main_bar += success_bar
        }
        else if (xml_status && !app_status && !vul_status){
            main_bar += success_bar
            
        }
        else if (app_status && !xml_status && !vul_status){
            main_bar += success_bar
        }
        else if (vul_status && !app_status && !xml_status){
            main_bar += success_bar
        }
    }
    main_bar += '</div>'
    return main_bar
}

function get_status_button(completed, status){
    if (status){
        status_btn = '<button class="btn btn-success btn-transparent btn-xs sshyze_ok_btn_pd">Accepted</button>'
    }
    else if (!status && !completed) {
        status_btn = '<button class="btn btn-success btn-transparent btn-xs sshyze_ok_btn_pd">Processing</button>'
    }
    else{
        status_btn = '<button class="btn btn-danger btn-transparent btn-xs sshyze_ok_btn_pd">Rejected</button>'
    }
    return status_btn
}

function DeleteNessusFile(obj){
    var id = $(obj).val()
    var query_url = '/nessus/delete-file/' + id
    $.ajax({
        url: query_url,
        type: "DELETE",
        data: {
            'pk': id
        },
        dataType: 'json',
        success: function(response){
            if (response.ok == true){
                var dl_tr_id = "#file_" + id
                $(dl_tr_id).hide()
                $.growl.notice({title:"Success", message: response.message});
            }
        }
    });
}

function file_delete_btn(file_id){
    // var btn
    btn = "<button type='button' class='btn btn-info btn-xs' value='" + file_id + "' onclick='DeleteNessusFile(this);'>Delete</button>"
    return btn
}



function create_nessus_file_table(){
    $.ajax({
        url: '/nessus/files',
        type: "GET",
        dataType: 'json',
        success: function(response){
            $('#nessus-files-tb').html('');
            $.each(response, function(i, item){
                var table_tr = '<tr id="file_'+ item.id +'">'
                var total_findings_td = '<td id="total_finding_'+ item.id + '">'
                total_findings_td += get_risk_button('critical', item.critical_risk_count)
                total_findings_td += get_risk_button('high', item.high_risk_count)
                total_findings_td += get_risk_button('medium', item.medium_risk_count)
                total_findings_td += get_risk_button('low', item.low_risk_count)
                total_findings_td += '</td>'
                var new_findings_td = '<td id="new_finding_'+ item.id + '">'
                new_findings_td += get_risk_button('critical', item.critical_new_issue)
                new_findings_td += get_risk_button('high', item.high_new_issue)
                new_findings_td += get_risk_button('medium', item.medium_new_issue)
                new_findings_td += get_risk_button('low', item.low_new_issue)
                new_findings_td += '</td>'
                var file_code = '<td>' + item.filename + '</td>'
                if (item.hosts_list){
                    var rj_title = "File rejected. Hosts not found in db view detail for more."
                }
                else{
                    var rj_title = ''
                }
                var file_status = '<td title="'+ rj_title +'">' + get_status_button(item.is_completed, item.is_accepted) + '</td>'
                var date = '<td>' + item.uploaded_at + '</td>'
                var detail = '<td><a href="/nessus/file/'
                detail += item.file_code + '">View</a></td>'
                var action_dl = file_delete_btn(item.id)
                var action = '<td>' + action_dl + '</td>'
                // action += item.id + '">Delete</a></td>'
                if (item.error_message){
                    var progress_bar = '<td title="'+ item.error_message +'">'
                }
                else{
                    var progress_bar = '<td>'
                }
                
                progress_bar += get_progress_bar(
                    item.xml_process_status,
                    item.applications_process_status,
                    item.vulnerabilities_process_status,
                    item.is_completed
                )
                progress_bar += '</td>'
                table_tr += total_findings_td
                table_tr += new_findings_td
                table_tr += file_code
                table_tr += file_status
                table_tr += date
                table_tr += detail

                table_tr += progress_bar
                table_tr += action
                table_tr += '</tr>'
                $('#nessus-files-tb').append(table_tr)
            })
        },
        error: function(xhr, ajaxOption, thrownError){
            console.log(thrownError)
        }
    });
}



$(document).ready(function(){
    create_nessus_file_table();
});