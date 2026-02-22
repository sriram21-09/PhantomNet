// frontend/src/hooks/usePagination.js
import { useState, useMemo } from "react";

export const usePagination = (data, itemsPerPage = 10) => {
    const [currentPage, setCurrentPage] = useState(1);

    const paginatedData = useMemo(() => {
        if (!data) return [];
        const startIndex = (currentPage - 1) * itemsPerPage;
        return data.slice(startIndex, startIndex + itemsPerPage);
    }, [data, currentPage, itemsPerPage]);

    const totalPages = useMemo(() => {
        if (!data) return 0;
        return Math.ceil(data.length / itemsPerPage);
    }, [data, itemsPerPage]);

    const goToPage = (pageNumber) => {
        const page = Math.max(1, Math.min(pageNumber, totalPages));
        setCurrentPage(page);
    };

    const nextPage = () => goToPage(currentPage + 1);
    const prevPage = () => goToPage(currentPage - 1);

    return {
        currentPage,
        totalPages,
        paginatedData,
        goToPage,
        nextPage,
        prevPage,
        startIndex: (currentPage - 1) * itemsPerPage,
    };
};
