document.addEventListener("DOMContentLoaded", function() {
    const tableBody = document.getElementById('table-body');
    const totalRecordsSpan = document.getElementById('total-records');
    const recordRangeSpan = document.getElementById('record-range');
    const prevPageBtn = document.getElementById('prev-page');
    const nextPageBtn = document.getElementById('next-page');
    const resultsPerPageSelect = document.getElementById('results-per-page');

    let currentPage = 1;
    let totalRecords = 0;
    let recordsPerPage = parseInt(resultsPerPageSelect.value);

    function fetchCVEData(page, limit) {
        fetch(`http://localhost:3000/cve?page=${page}&limit=${limit}`)
            .then(response => response.json())
            .then(data => {
                tableBody.innerHTML = '';
                data.forEach(entry => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${entry.CVE_ID}</td>
                        <td>${entry.IDENTIFIER}</td>
                        <td>${entry.PUBLISHED_DATE}</td>
                        <td>${entry.LAST_MODIFIED_DATE}</td>
                        <td>${entry.STATUS}</td>
                    `;
                    tableBody.appendChild(row);
                });
                totalRecords = data.length;
                updatePagination();
            })
            .catch(error => console.error('Error fetching data:', error));
    }

    function updatePagination() {
        const start = (currentPage - 1) * recordsPerPage + 1;
        const end = Math.min(start + recordsPerPage - 1, totalRecords);
        recordRangeSpan.textContent = `${start}-${end} of ${totalRecords} records`;
        prevPageBtn.disabled = currentPage === 1;
        nextPageBtn.disabled = end >= totalRecords;
    }

    fetchCVEData(currentPage, recordsPerPage);

    prevPageBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            fetchCVEData(currentPage, recordsPerPage);
        }
    });

    nextPageBtn.addEventListener('click', () => {
        if (currentPage < Math.ceil(totalRecords / recordsPerPage)) {
            currentPage++;
            fetchCVEData(currentPage, recordsPerPage);
        }
    });

    resultsPerPageSelect.addEventListener('change', () => {
        recordsPerPage = parseInt(resultsPerPageSelect.value);
        currentPage = 1;
        fetchCVEData(currentPage, recordsPerPage);
    });
});