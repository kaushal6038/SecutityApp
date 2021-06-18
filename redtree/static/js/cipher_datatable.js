$(document).ready(function() {
    $('#cipher-datatable').DataTable( {
        // "searching": false,
        "paging":   false,
        "columnDefs": [ {
            "targets": 'no-sort',
            "orderable": false,
        },
        { 
            "searchable"    : false, 
            "targets"       : [0,3,4,5,6,7,8,9] 
        },]
    } );

    // DataTable
    var table = $('#cipher-datatable').DataTable();
    // Apply the search for openssl
    table.columns(1).every( function () {
        var that = this;
        $( '.datatable_input_openssl', this.footer() ).on( 'keyup change', function () {
            if ( that.search() !== this.value ) {
                that
                    .search( this.value )
                    .draw();
            }
        } );
    } );
    // Apply the search for iana
    table.columns(2).every( function () {
        var that = this;
        $( '.datatable_input_iana', this.footer() ).on( 'keyup change', function () {
            if ( that.search() !== this.value ) {
                that
                    .search( this.value )
                    .draw();
            }
        } );
    } );
} );