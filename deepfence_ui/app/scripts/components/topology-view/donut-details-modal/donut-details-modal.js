// React imports
import React, { useCallback, useMemo } from 'react';
import { connect, useDispatch } from 'react-redux';

import {
  closeDonutDetailsModal,
  getVulnerabilitiesAction,
  updateTableJSONModalView,
} from '../../../actions/app-actions';
import { fetchNodeSpecificDetails } from '../../../utils/web-api-utils';
import DFTable from '../../common/df-table/index';

class DonutDetailsModal extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      activeIndex: 0,
      recordsPerPage: 20,
      sortOrder: 'asc',
    };
    this.onClickClose = this.onClickClose.bind(this);
    this.handlePageChange = this.handlePageChange.bind(this);
    this.resetTableUI = this.resetTableUI.bind(this);
  }

  componentDidMount() {
    // On page load call
    this.fetchAlertsDetails();

    // Calls on the basis of active time interval
    if (this.props.refreshInterval) {
      const interval = setInterval(() => {
        // this.fetchNodeDetails();
        this.fetchAlertsDetails();
      }, this.props.refreshInterval.value * 1000);
      this.setState({ intervalObj: interval });
    }
  }

  UNSAFE_componentWillReceiveProps(newProps) {
    if (
      newProps.refreshInterval &&
      this.props.refreshInterval !== newProps.refreshInterval
    ) {
      const interval = setInterval(() => {
        const activeDuration = newProps.days.value;
        this.updateTable(activeDuration.number, activeDuration.time_unit);
      }, newProps.refreshInterval.value * 1000);
      if (this.state.intervalObj) {
        clearInterval(this.state.intervalObj);
      }
      this.setState({ intervalObj: interval });
    }
    if (
      newProps.activeSector !== this.props.activeSector ||
      newProps.activeDonut !== this.props.activeDonut
    ) {
      // Resetting sorting UI
      this.resetTableUI();
    }
    if (this.props.days !== newProps.days) {
      this.updateTable(
        newProps.days.value.number,
        newProps.days.value.time_unit
      );
    }
  }

  componentWillUnmount() {
    if (this.state.intervalObj) {
      clearInterval(this.state.intervalObj);
    }
  }

  resetTableUI() {
    this.setState({ sortOrder: 'asc' });
  }

  updateTable(number, time_unit) {
    const { fetchAlertsDetails } = this;
    this.setState({ sortOrder: 'asc', forcePage: 0, activeIndex: 0 }, () => {
      fetchAlertsDetails(number, time_unit);
    });
    setTimeout(() => {
      if (this.state.forcePage === 0) {
        this.setState({ forcePage: undefined });
      }
    }, 0);
  }

  fetchAlertsDetails(number, time_unit) {
    const {
      kubeNamespace = '',
      activePod = '',
      activeDonut,
      activeSector,
      activeNode,
      activeHost,
    } = this.props;

    if (activeDonut === 'severity') {
      fetchNodeSpecificDetails(
        this.props.dispatch,
        activeSector,
        activeDonut,
        activeNode,
        activeHost,
        kubeNamespace,
        activePod,
        this.props.activeTopologyId,
        this.props.destinationIp,
        this.props.containerIdArr,
        this.state.activeIndex,
        this.state.recordsPerPage,
        this.state.sortOrder,
        this.props.activeFilter,
        this.props.activeOptions,
        number || this.props.days.value.number,
        time_unit || this.props.days.value.time_unit
      );
    } else if (activeDonut === 'cve_severity') {
      // HACK: Overriding names used for alert severity.
      // CVE severity introduced in Feb 2020.
      // This component is not configurable to fetch the user defined types
      // The names are not at all intuitive but in the interest of time,
      // lets keep it this way.
      const imageName = activeNode;
      const severity = activeSector;
      const scanId = activeHost;
      this.fetchVulnerabilities(imageName, scanId, severity);
    }
  }

  fetchVulnerabilities(imageName, scanId, severity) {
    const { dispatch } = this.props;

    const params = {
      type: 'cve',
      query: {
        from: this.state.activeIndex,
        size: this.state.recordsPerPage,
      },
      filters: {
        masked: ['false'],
        type: ['cve'],
        cve_severity: severity,
        cve_container_image: imageName,
        scan_id: scanId,
      },
    };
    return dispatch(getVulnerabilitiesAction(params));
  }

  handlePageChange(data) {
    if (data.selected !== 0) {
      this.setState(state => ({
        activeIndex: data.selected * state.recordsPerPage,
      }));
    } else {
      this.setState({ activeIndex: data.selected });
    }
    setTimeout(() => {
      this.fetchAlertsDetails();
    }, 0);
  }

  onClickClose() {
    this.props.dispatch(closeDonutDetailsModal());
  }

  sortTimeStamp() {
    const { sortOrder } = this.state;
    if (sortOrder === 'asc') {
      this.setState({ sortOrder: 'desc' });
    } else {
      this.setState({ sortOrder: 'asc' });
    }
    setTimeout(() => {
      this.fetchAlertsDetails();
    }, 0);
  }

  render() {
    let nodeDetails;
    const { nodeSpecificDetails } = this.props;
    if (nodeSpecificDetails && nodeSpecificDetails.data.hits !== 0) {
      nodeDetails = nodeSpecificDetails.data.hits;
    } else {
      nodeDetails = nodeSpecificDetails;
    }

    const { recordsPerPage } = this.state;

    if (nodeSpecificDetails === undefined) {
      return null;
    }

    const totalPages = Math.ceil(
      nodeSpecificDetails.data.total / recordsPerPage
    );

    return (
      <div className="chart-details-wrapper">
        <div className="modal-header">
          <div className="header-text">Vulnerabilities</div>
          <div
            title="Close details"
            className="fa fa-close"
            onClick={this.onClickClose}
          />
        </div>
        <div className="modal-body node-vulnerabilities">
          <Table
            data={nodeDetails}
            numPages={totalPages}
            pageSize={recordsPerPage}
            onPageChange={this.handlePageChange}
          />
        </div>
      </div>
    );
  }
}

function mapStateToProps(state) {
  return {
    nodeSpecificDetails: state.get('nodeSpecificDetails'),
    activeDonut: state.get('activeDonut'),
    activeSector: state.get('activeSector'),
    activeNode: state.get('activeNode'),
    activeHost: state.get('activeHost'),
    kubeNamespace: state.get('kubeNamespace'),
    activePod: state.get('activePod'),
    activeTopologyId: state.get('activeTopologyId'),
    destinationIp: state.get('destinationIp'),
    containerIdArr: state.get('containerIdArr'),
    activeFilter: state.get('activeFilter'),
    activeOptions: state.get('activeOptions'),
    days: state.get('alertPanelHistoryBound'),
    refreshInterval: state.get('refreshInterval'),
  };
}

export default connect(mapStateToProps)(DonutDetailsModal);

const Table = ({ data, numPages, pageSize, onPageChange }) => {
  const dispatch = useDispatch();

  const rows = useMemo(() => data?.map(doc => doc._source), [data]);

  const onRowClick = useCallback(
    doc => {
      dispatch(updateTableJSONModalView({ data: { _source: doc } }));
    },
    [dispatch]
  );

  const onFetchData = useCallback(
    state => {
      onPageChange({ selected: state.page });
    },
    [onPageChange]
  );

  if (rows === undefined) {
    return null;
  }

  return (
    <DFTable
      getTdProps={(state, rowInfo) => ({
        onClick: () => onRowClick(rowInfo.original),
        style: {
          cursor: 'pointer',
        },
      })}
      manual
      data={rows}
      minRows={0}
      showPagination
      defaultPageSize={pageSize}
      pages={numPages * pageSize}
      onFetchData={onFetchData}
      sortable={false}
      columns={[
        {
          Header: 'CVE ID',
          accessor: 'cve_id',
          maxWidth: 200,
          Cell: row => (
            <div className="truncate" title={row.value}>
              {row.value}
            </div>
          ),
        },
        {
          Header: 'Severity',
          accessor: 'cve_severity',
          maxWidth: 150,
          Cell: row => (
            <div className={`${row.value}-severity`}>{row.value}</div>
          ),
        },
        {
          Header: 'Package',
          accessor: 'cve_caused_by_package',
          maxWidth: 200,
          Cell: row => (
            <div className="truncate" title={row.value}>
              {row.value}
            </div>
          ),
        },
        {
          Header: 'Description',
          accessor: 'cve_description',
          Cell: row => (
            <div className="truncate" title={row.value}>
              {row.value}
            </div>
          ),
        },
        {
          Header: 'Link',
          accessor: 'cve_link',
          Cell: row => (
            <div className="truncate" title={row.value}>
              <a href={row.value} target="_blank" rel="noreferrer">
                {row.value}
              </a>
            </div>
          ),
        },
      ]}
    />
  );
};
