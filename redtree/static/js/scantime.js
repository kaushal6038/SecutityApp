function add_nessus_scan_time(obj)
    {
        var job_hour = $("#nessus_add_scan_job_hour_id").val();
        var job_min = $("#nessus_add_scan_job_min_id").val();
        $.ajax({
            url: '/playground/add-scan-time/',
            type: 'POST',
            data: {
                'hour': job_hour,
                'min': job_min,
                'service': "nessus_add_scan"
                },
            dataType: 'json',
            success: function(response){
            	if (response){
                    $.growl.notice({title:"Success", message: "Add Scan time added successfully!"});
            	}
            }
       });
    }

function add_masscan_scan_time(obj)
    {
        var job_hour = $("#masscan_job_hour_id").val();
        var job_min = $("#masscan_job_min_id").val();
        $.ajax({
            url: '/playground/add-scan-time/',
            type: 'POST',
            data: {
                'hour': job_hour,
                'min': job_min,
                'service': "masscan"
                },
            dataType: 'json',
            success: function(response){
                if (response){
                    $.growl.notice({title:"Success", message: "Scan time added successfully!"});
                }
            }
       });
    }

function add_sslyze_scan_time(obj)
    {
        var job_hour = $("#sslyze_job_hour_id").val();
        var job_min = $("#sslyze_job_min_id").val();
        $.ajax({
            url: '/playground/add-scan-time/',
            type: 'POST',
            data: {
                'hour': job_hour,
                'min': job_min,
                'service': "sslyze"
                },
            dataType: 'json',
            success: function(response){
                if (response){
                    $.growl.notice({title:"Success", message: "Scan time added successfully!"});
                }
            }
       });
    }

function add_sshyze_scan_time(obj)
    {
        var job_hour = $("#sshyze_job_hour_id").val();
        var job_min = $("#sshyze_job_min_id").val();
        $.ajax({
            url: '/playground/add-scan-time/',
            type: 'POST',
            data: {
                'hour': job_hour,
                'min': job_min,
                'service': "sshyze"
                },
            dataType: 'json',
            success: function(response){
                if (response){
                    $.growl.notice({title:"Success", message: "Scan time added successfully!"});
                }
            }
       });
    }


function add_burp_scan_time(obj)
    {
        var job_hour = $("#burp_job_hour_id").val();
        var job_min = $("#burp_job_min_id").val();
        $.ajax({
            url: '/playground/add-scan-time/',
            type: 'POST',
            data: {
                'hour': job_hour,
                'min': job_min,
                'service': "burp"
                },
            dataType: 'json',
            success: function(response){
                if (response){
                    $.growl.notice({title:"Success", message: "Scan time added successfully!"});
                }
            }
       });
    }


function add_dnsenum_scan_time(obj)
    {
        var job_hour = $("#dnsenum_job_hour_id").val();
        var job_min = $("#dnsenum_job_min_id").val();
        $.ajax({
            url: '/playground/add-scan-time/',
            type: 'POST',
            data: {
                'hour': job_hour,
                'min': job_min,
                'service': "dnsenum"
                },
            dataType: 'json',
            success: function(response){
                if (response){
                    $.growl.notice({title:"Success", message: "Scan time added successfully!"});
                }
            }
       });
    }


function add_screenshot_scan_time(obj)
{
    var job_hour = $("#screenshot_job_hour_id").val();
    var job_min = $("#screenshot_job_min_id").val();
    $.ajax({
        url: '/playground/add-scan-time/',
        type: 'POST',
        data: {
            'hour': job_hour,
            'min': job_min,
            'service': "screenshot"
            },
        dataType: 'json',
        success: function(response){
            if (response){
                $.growl.notice({title:"Success", message: "Scan time added successfully!"});
            }
        }
   });
}


function add_cloudstorage_scan_time(obj)
{
    var job_hour = $("#cloudstorage_job_hour_id").val();
    var job_min = $("#cloudstorage_job_min_id").val();
    $.ajax({
        url: '/playground/add-scan-time/',
        type: 'POST',
        data: {
            'hour': job_hour,
            'min': job_min,
            'service': "cloudstorage"
            },
        dataType: 'json',
        success: function(response){
            if (response){
                $.growl.notice({
                    title:"Success",
                    message: "Scan time added successfully!"
                });
            }
        }
   });
}


function add_whois_scan_time(obj)
{
    var job_hour = $("#whois_job_hour_id").val();
    var job_min = $("#whois_job_min_id").val();
    $.ajax({
        url: '/playground/add-scan-time/',
        type: 'POST',
        data: {
            'hour': job_hour,
            'min': job_min,
            'service': "whois"
            },
        dataType: 'json',
        success: function(response){
            if (response){
                $.growl.notice({
                    title:"Success",
                    message: "Scan time added successfully!"
                });
            }
        }
   });
}

function add_rds_scan_time(obj)
{
    var job_hour = $("#rds_job_hour_id").val();
    var job_min = $("#rds_job_min_id").val();
    $.ajax({
        url: '/playground/add-scan-time/',
        type: 'POST',
        data: {
            'hour': job_hour,
            'min': job_min,
            'service': "rds_scan"
            },
        dataType: 'json',
        success: function(response){
            if (response){
                $.growl.notice({
                    title:"Success",
                    message: "Scan time added successfully!"
                });
            }
        }
   });
}

function add_awsasset_scan_time(obj)
{
    var job_hour = $("#awsasset_job_hour_id").val();
    var job_min = $("#awsasset_job_min_id").val();
    $.ajax({
        url: '/playground/add-scan-time/',
        type: 'POST',
        data: {
            'hour': job_hour,
            'min': job_min,
            'service': "aws_asset_scan"
            },
        dataType: 'json',
        success: function(response){
            if (response){
                $.growl.notice({
                    title:"Success",
                    message: "Scan time added successfully!"
                });
            }
        }
   });
}